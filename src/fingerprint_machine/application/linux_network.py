"""The ``network`` section of a Linux reading: one record per interface, as on Windows.

Like the Windows section, the reading is ``adapters`` (one record per interface, with its
``ip_addresses`` and ``routes`` joined to it by interface index) and ``unmatched`` (what names an
interface that does not exist). Each record holds what sysfs says (address, MTU, type, flags,
carrier, speed, duplex, queues), the PCI function behind the interface and the bridges above it,
what ethtool says (driver, firmware, bus address, the burned-in address, every offload feature,
ring sizes, channels, interrupt coalescing, link modes, pause frames, wake-on-LAN), what rtnetlink
says about the link, and its neighbours. The resolver configuration closes the section.

ethtool questions a driver does not answer, or that need ``CAP_NET_ADMIN``, are recorded as such
per question. A netlink table is read once for all interfaces and kept to
:data:`MAX_TABLE_ENTRIES` rows, so a router's full table cannot grow a reading without bound.

Contents:
    * :data:`MAX_TABLE_ENTRIES` - the most rows kept from one netlink table.
    * :func:`read_linux_network` - read the section.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, NamedTuple

from ..domain.blockdev import pci_addresses
from ..domain.ethtool import (
    CHANNELS,
    COALESCE,
    PAUSE,
    RINGS,
    StringSet,
    U32Fields,
    decode_driver_info,
    decode_features,
    decode_link_settings,
    decode_permanent_address,
    decode_string_count,
    decode_strings,
    decode_wake_on_lan,
    driver_info_request,
    features_request,
    link_settings_request,
    link_settings_words,
    permanent_address_request,
    string_count_request,
    strings_request,
    wake_on_lan_request,
)
from ..domain.machine_errors import MissingPathError
from ..domain.netlink import decode_address, decode_link, decode_neighbour, decode_route, hardware_type, interface_flags
from ..domain.resolv import parse_resolv_conf
from .guard import ANSWER_ERRORS, guarded
from .linux_files import optional_dir
from .linux_leaves import Leaf, flag, integer, pci_function, read_leaves
from .machine_ports import NetlinkDump

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

_NET = "/sys/class/net"
#: The most rows kept from one netlink table; past it the table is marked truncated.
MAX_TABLE_ENTRIES = 10_000

_INTERFACE_LEAVES = (
    Leaf("ifindex", integer), Leaf("address"), Leaf("broadcast"), Leaf("addr_assign_type", integer),
    Leaf("addr_len", integer), Leaf("mtu", integer), Leaf("type", lambda raw: hardware_type(int(raw))),
    Leaf("flags", lambda raw: interface_flags(int(raw, 16))), Leaf("carrier", flag), Leaf("speed", integer),
    Leaf("duplex"), Leaf("operstate"), Leaf("tx_queue_len", integer), Leaf("dev_port", integer), Leaf("dev_id"),
    Leaf("phys_port_name"), Leaf("phys_port_id"), Leaf("phys_switch_id"), Leaf("ifalias"), Leaf("iflink", integer),
    Leaf("link_mode", integer), Leaf("netdev_group", integer), Leaf("name_assign_type", integer),
    Leaf("proto_down", flag),
)  # fmt: skip


# ---------------------------------------------------------------------------------------------
# ethtool: one guarded question each.
# ---------------------------------------------------------------------------------------------


def _names(src: LinuxSource, ifname: str, string_set: StringSet) -> list[str]:
    count = decode_string_count(src.ethtool(ifname, request=string_count_request(string_set)))
    return decode_strings(src.ethtool(ifname, request=strings_request(string_set, count)))


def _features(src: LinuxSource, ifname: str) -> JsonValue:
    names = _names(src, ifname, StringSet.FEATURES)
    return decode_features(src.ethtool(ifname, request=features_request(len(names))), names)


def _link_settings(src: LinuxSource, ifname: str) -> JsonValue:
    words = link_settings_words(src.ethtool(ifname, request=link_settings_request(0)))
    answer = src.ethtool(ifname, request=link_settings_request(words))
    try:
        names = _names(src, ifname, StringSet.LINK_MODES)
    except ANSWER_ERRORS:
        names = []  # a kernel without the name table: every mode is still kept, as bit<N>
    return decode_link_settings(answer, names)


def _fields(table: U32Fields) -> Callable[[LinuxSource, str], JsonValue]:
    return lambda src, ifname: table.decode(src.ethtool(ifname, request=table.request()))


_ETHTOOL: Mapping[str, Callable[[LinuxSource, str], JsonValue]] = {
    "driver": lambda src, ifname: decode_driver_info(src.ethtool(ifname, request=driver_info_request())),
    "permanent_address": lambda src, ifname: decode_permanent_address(
        src.ethtool(ifname, request=permanent_address_request())
    ),
    "features": _features,
    "link_settings": _link_settings,
    "rings": _fields(RINGS),
    "channels": _fields(CHANNELS),
    "coalesce": _fields(COALESCE),
    "pause": _fields(PAUSE),
    "wake_on_lan": lambda src, ifname: decode_wake_on_lan(src.ethtool(ifname, request=wake_on_lan_request())),
}


# ---------------------------------------------------------------------------------------------
# rtnetlink: each table read once, its rows given to the interface they name.
# ---------------------------------------------------------------------------------------------


class _Table:
    """The rows of one netlink table by interface index, and what the dump recorded about itself."""

    def __init__(self, *, key: str) -> None:
        self.rows: dict[int | None, list[JsonValue]] = {}
        self._key = key

    def read(self, messages: Iterable[bytes], decode: Callable[[bytes], JsonObject]) -> JsonValue:
        """Decode every message (each guarded), keep at most :data:`MAX_TABLE_ENTRIES` rows."""
        count = 0
        for message in messages:
            if count == MAX_TABLE_ENTRIES:
                return {"rows": count, "truncated": True}
            row = guarded(lambda message=message: decode(message))
            index = row.get(self._key) if isinstance(row, dict) else None
            self.rows.setdefault(index if isinstance(index, int) else None, []).append(row)
            count += 1
        return {"rows": count, "truncated": False}

    def take(self, index: JsonValue) -> list[JsonValue]:
        """Remove and return the rows of one interface."""
        return self.rows.pop(index, []) if isinstance(index, int) else []

    def leftover(self) -> list[JsonValue]:
        """The rows no interface took, in index order (rows naming no index last)."""
        out: list[JsonValue] = []
        for index in sorted(self.rows, key=lambda i: (i is None, i or 0)):
            out.extend(self.rows[index])
        return out


class NetTable(StrEnum):
    """The netlink tables, by the name an interface record lists their rows under."""

    LINKS = "netlink"
    ADDRESSES = "ip_addresses"
    ROUTES = "routes"
    NEIGHBOURS = "neighbours"


class _TableSpec(NamedTuple):
    """How one netlink table is read: its dump, its decoder, and the row key naming the interface."""

    table: NetTable
    dump: NetlinkDump
    decode: Callable[[bytes], JsonObject]
    key: str


_TABLES: tuple[_TableSpec, ...] = (
    _TableSpec(NetTable.LINKS, NetlinkDump.LINKS, decode_link, "index"),
    _TableSpec(NetTable.ADDRESSES, NetlinkDump.ADDRESSES, decode_address, "index"),
    _TableSpec(NetTable.ROUTES, NetlinkDump.ROUTES, decode_route, "output_index"),
    _TableSpec(NetTable.NEIGHBOURS, NetlinkDump.NEIGHBOURS, decode_neighbour, "index"),
)


class _Tables(NamedTuple):
    """Every netlink table read once, and what each dump recorded about itself."""

    rows: Mapping[NetTable, _Table]
    status: JsonObject


def _tables(src: LinuxSource) -> _Tables:
    tables: dict[NetTable, _Table] = {}
    status: JsonObject = {}
    for spec in _TABLES:
        table = _Table(key=spec.key)
        status[spec.table.value] = guarded(
            lambda spec=spec, table=table: table.read(src.netlink_dump(spec.dump), spec.decode)
        )
        tables[spec.table] = table
    return _Tables(rows=MappingProxyType(tables), status=status)


# ---------------------------------------------------------------------------------------------
# One interface.
# ---------------------------------------------------------------------------------------------


def _queues(names: Sequence[str]) -> JsonObject:
    return {"rx": sum(n.startswith("rx-") for n in names), "tx": sum(n.startswith("tx-") for n in names)}


def _place(src: LinuxSource, directory: str) -> JsonObject:
    target = guarded(lambda: src.readlink(directory))
    chain: list[JsonValue] = []
    chain.extend(pci_addresses(target) if isinstance(target, str) else [])
    function = chain[-1] if chain else None
    return {
        "device_path": target,
        "pci_chain": chain,
        "pci": guarded(lambda: pci_function(src, str(function))) if function is not None else None,
    }


def _interface(src: LinuxSource, name: str, tables: Mapping[NetTable, _Table]) -> JsonObject:
    directory = f"{_NET}/{name}"
    sysfs = read_leaves(src, directory, _INTERFACE_LEAVES)
    index = sysfs.get("ifindex")
    links = tables[NetTable.LINKS].take(index)
    record: JsonObject = {
        "name": name,
        "index": index,
        **_place(src, directory),
        "sysfs": sysfs,
        "queues": guarded(lambda: _queues(src.list_dir(f"{directory}/queues"))),
        "netlink": links[0] if links else None,
    }
    for question, ask in _ETHTOOL.items():
        record[question] = guarded(lambda ask=ask: ask(src, name))
    for table in (NetTable.ADDRESSES, NetTable.ROUTES, NetTable.NEIGHBOURS):
        record[table.value] = tables[table].take(index)
    return record


def _interfaces(src: LinuxSource) -> list[str]:
    """The interface names; ``bonding_masters`` and other plain files in the class are skipped."""
    return [name for name in src.list_dir(_NET) if "ifindex" in _names_or_none(src, f"{_NET}/{name}")]


def _names_or_none(src: LinuxSource, path: str) -> list[str]:
    try:
        return src.list_dir(path)
    except MissingPathError:  # a file in the class directory (ENOTDIR)
        return []


def _dns(src: LinuxSource) -> JsonObject:
    resolved = "/run/systemd/resolve/resolv.conf"
    out: JsonObject = {"resolv_conf": guarded(lambda: parse_resolv_conf(src.read_text("/etc/resolv.conf")).as_json())}
    # systemd-resolved keeps the upstream servers here when /etc/resolv.conf names its stub.
    if "resolv.conf" in optional_dir(src, "/run/systemd/resolve"):
        out["systemd_resolved"] = guarded(lambda: parse_resolv_conf(src.read_text(resolved)).as_json())
    return out


def read_linux_network(src: LinuxSources) -> JsonValue:
    """Read every network interface with its ethtool answers, addresses, routes and neighbours."""
    system = src.system
    tables = _tables(system)
    adapters: list[JsonValue] = [
        guarded(lambda name=name: _interface(system, name, tables.rows)) for name in _interfaces(system)
    ]
    return {
        "adapters": adapters,
        "unmatched": {name.value: table.leftover() for name, table in tables.rows.items() if table.rows},
        "dns": _dns(system),
        "tables": tables.status,
    }


__all__ = ["MAX_TABLE_ENTRIES", "NetTable", "read_linux_network"]
