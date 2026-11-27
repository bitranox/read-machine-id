"""rtnetlink: the dump requests for links, addresses, routes and neighbours, and their decoding.

The kernel answers an rtnetlink dump with a stream of messages, each a ``struct nlmsghdr``, a
fixed family header and a list of attributes (``struct rtattr``: length, type, value, padded to 4
bytes). Layouts follow ``include/uapi/linux/netlink.h``, ``rtnetlink.h``, ``if_link.h``,
``if_addr.h`` and ``neighbour.h``. Attributes not named here (statistics, which change every
second, and nested per-driver blobs) are left out.

Interface flags and the hardware type are named here as well, since ``/sys/class/net/<if>/flags``
and ``type`` carry the same numbers the link messages do.

Contents:
    * :class:`DumpKind` - the four dumps, each with its request message type.
    * :func:`dump_request` - the request message for one dump.
    * :func:`split_messages` - the messages of one received buffer.
    * :func:`message_type`, :func:`error_number` - what a message is.
    * :func:`decode_link`, :func:`decode_address`, :func:`decode_route`, :func:`decode_neighbour`.
    * :func:`interface_flags`, :func:`hardware_type` - the numbers sysfs and netlink share, by name.

Every dump has its request header:

    >>> from fingerprint_machine.domain.netlink import _REQUEST_BODY
    >>> set(_REQUEST_BODY) == set(DumpKind)
    True
"""

from __future__ import annotations

import ipaddress
import struct
from enum import IntEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

    from .json_types import JsonObject, JsonValue

_HEADER = struct.Struct("<IHHII")
_ATTR = struct.Struct("<HH")
_IFINFO = struct.Struct("<BxHiII")
_IFADDR = struct.Struct("<BBBBI")
_RTMSG = struct.Struct("<BBBBBBBBI")
_NDMSG = struct.Struct("<BxxxiHBB")
_ERROR = struct.Struct("<i")
_NLM_F_REQUEST = 0x01
_NLM_F_DUMP = 0x300
_NLA_TYPE_MASK = 0x3FFF
_DONE = 3
_ERROR_TYPE = 2
_AF_INET = 2
_AF_INET6 = 10
_IFA_FLAGS = 8
_RTA_DST = 1
_RTA_SRC = 2
_RTA_TABLE = 15
_NDA_DST = 1
_NDA_LLADDR = 2


class DumpKind(IntEnum):
    """The rtnetlink dumps read, each valued by its request message type (``RTM_GET*``)."""

    LINKS = 18
    ADDRESSES = 22
    ROUTES = 26
    NEIGHBOURS = 30


# The family header each request carries, all zero (every family, every interface).
_REQUEST_BODY = MappingProxyType(
    {
        DumpKind.LINKS: _IFINFO.size,
        DumpKind.ADDRESSES: _IFADDR.size,
        DumpKind.ROUTES: _RTMSG.size,
        DumpKind.NEIGHBOURS: _NDMSG.size,
    }
)

_FAMILIES = MappingProxyType({0: "unspec", 2: "ipv4", 7: "bridge", 10: "ipv6", 17: "packet", 28: "mpls"})
# IFF_* in bit order (include/uapi/linux/if.h).
_IFF = (
    "up", "broadcast", "debug", "loopback", "pointopoint", "notrailers", "running", "noarp",
    "promisc", "allmulti", "master", "slave", "multicast", "portsel", "automedia", "dynamic",
    "lower_up", "dormant", "echo",
)  # fmt: skip
# ARPHRD_* (include/uapi/linux/if_arp.h): the hardware types a fingerprint meets.
_ARPHRD = MappingProxyType({
    1: "ether", 24: "ieee1394", 32: "infiniband", 512: "ppp", 768: "tunnel", 769: "tunnel6",
    772: "loopback", 776: "sit", 778: "ipgre", 801: "ieee80211", 803: "ieee80211_radiotap",
    823: "ip6gre", 65534: "none",
})  # fmt: skip
_OPERSTATES = ("unknown", "notpresent", "down", "lowerlayerdown", "testing", "dormant", "up")
# IFA_F_* in bit order (include/uapi/linux/if_addr.h).
_IFA_FLAG_NAMES = (
    "secondary", "nodad", "optimistic", "dadfailed", "homeaddress", "deprecated", "tentative",
    "permanent", "managetempaddr", "noprefixroute", "mcautojoin", "stable_privacy",
)  # fmt: skip
_SCOPES = MappingProxyType({0: "universe", 200: "site", 253: "link", 254: "host", 255: "nowhere"})
_TABLES = MappingProxyType({253: "default", 254: "main", 255: "local"})
_PROTOCOLS = MappingProxyType({
    0: "unspec", 1: "redirect", 2: "kernel", 3: "boot", 4: "static", 9: "ra", 11: "zebra",
    12: "bird", 16: "dhcp", 18: "keepalived", 42: "babel", 186: "bgp", 187: "isis", 188: "ospf",
    189: "rip",
})  # fmt: skip
_ROUTE_TYPES = (
    "unspec", "unicast", "local", "broadcast", "anycast", "multicast", "blackhole",
    "unreachable", "prohibit", "throw", "nat", "xresolve",
)  # fmt: skip
# NUD_* in bit order (include/uapi/linux/neighbour.h).
_NUD = ("incomplete", "reachable", "stale", "delay", "probe", "failed", "noarp", "permanent")


def _flag_names(value: int, names: tuple[str, ...]) -> list[JsonValue]:
    out: list[JsonValue] = []
    out.extend(name for bit, name in enumerate(names) if value >> bit & 1)
    out.extend(f"bit{bit}" for bit in range(len(names), 32) if value >> bit & 1)
    return out


def _named(value: int, names: Mapping[int, str]) -> str:
    return names.get(value, str(value))


def _indexed(value: int, names: tuple[str, ...]) -> str:
    return names[value] if 0 <= value < len(names) else str(value)


def interface_flags(value: int) -> list[JsonValue]:
    """Return the names of the ``IFF_*`` flags set in ``value``.

    Example:
        >>> interface_flags(0x1043)
        ['up', 'broadcast', 'running', 'multicast']
    """
    return _flag_names(value, _IFF)


def hardware_type(value: int) -> str:
    """Return the name of an ``ARPHRD_*`` hardware type, or its number when unnamed.

    Example:
        >>> hardware_type(1), hardware_type(9999)
        ('ether', '9999')
    """
    return _named(value, _ARPHRD)


def dump_request(kind: DumpKind, *, sequence: int) -> bytes:
    """Return the request message for one dump of every entry of ``kind``.

    Example:
        >>> len(dump_request(DumpKind.LINKS, sequence=1))
        32
    """
    body = bytes(_REQUEST_BODY[kind])
    return _HEADER.pack(_HEADER.size + len(body), kind, _NLM_F_REQUEST | _NLM_F_DUMP, sequence, 0) + body


def split_messages(buffer: bytes) -> Iterator[bytes]:
    """Yield each message of one received buffer, header included.

    Raises:
        ValueError: a message states a length the buffer does not hold.
    """
    offset = 0
    while offset + _HEADER.size <= len(buffer):
        length = _HEADER.unpack_from(buffer, offset)[0]
        if length < _HEADER.size or offset + length > len(buffer):
            raise ValueError(f"netlink message at offset {offset} states {length} bytes")
        yield buffer[offset : offset + length]
        offset += (length + 3) & ~3


def message_type(message: bytes) -> int:
    """Return the ``nlmsg_type`` of a message (``3`` ends a dump, ``2`` is an error).

    Raises:
        ValueError: the bytes are shorter than a message header.
    """
    if len(message) < _HEADER.size:
        raise ValueError(f"netlink message shorter than its {_HEADER.size}-byte header")
    return int(_HEADER.unpack_from(message)[1])


def error_number(message: bytes) -> int | None:
    """Return the errno an ``NLMSG_ERROR`` message carries; ``None`` for any other message."""
    if message_type(message) != _ERROR_TYPE:
        return None
    if len(message) < _HEADER.size + _ERROR.size:
        raise ValueError("netlink error message shorter than its error code")
    return -int(_ERROR.unpack_from(message, _HEADER.size)[0])


def is_done(message: bytes) -> bool:
    """Return whether a message ends the dump."""
    return message_type(message) == _DONE


def _attributes(data: bytes) -> dict[int, bytes]:
    """Return each attribute's value by type; a repeated type keeps the last."""
    out: dict[int, bytes] = {}
    offset = 0
    while offset + _ATTR.size <= len(data):
        length, kind = _ATTR.unpack_from(data, offset)
        if length < _ATTR.size or offset + length > len(data):
            raise ValueError(f"netlink attribute at offset {offset} states {length} bytes")
        out[kind & _NLA_TYPE_MASK] = data[offset + _ATTR.size : offset + length]
        offset += (length + 3) & ~3
    return out


def _all_attributes(data: bytes, wanted: int) -> list[bytes]:
    found: list[bytes] = []
    offset = 0
    while offset + _ATTR.size <= len(data):
        length, kind = _ATTR.unpack_from(data, offset)
        if length < _ATTR.size:
            break
        if kind & _NLA_TYPE_MASK == wanted:
            found.append(data[offset + _ATTR.size : offset + length])
        offset += (length + 3) & ~3
    return found


def _string(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _u32(raw: bytes) -> int:
    return int.from_bytes(raw[:4], "little")


def _mac(raw: bytes) -> str:
    return raw.hex(":")


def _ip(raw: bytes) -> str:
    if len(raw) in {4, 16}:
        return str(ipaddress.ip_address(raw))
    return raw.hex(":")


def _family(value: int) -> str:
    return _named(value, _FAMILIES)


class _Attr(NamedTuple):
    """One attribute a message may carry: its type number and how its value is decoded."""

    kind: int
    decode: Callable[[bytes], JsonValue]


class _Message(NamedTuple):
    """A message split into its fixed family header (unpacked) and its attribute bytes."""

    header: tuple[int, ...]
    attributes: bytes


def _fields(attrs: Mapping[int, bytes], spec: Mapping[str, _Attr]) -> JsonObject:
    """Return each attribute ``spec`` names that the message carries, decoded."""
    return {name: attr.decode(attrs[attr.kind]) for name, attr in spec.items() if attr.kind in attrs}


def _body(message: bytes, header: struct.Struct, kind: str) -> _Message:
    start = _HEADER.size
    if len(message) < start + header.size:
        raise ValueError(f"netlink {kind} message shorter than its header")
    return _Message(header=header.unpack_from(message, start), attributes=message[start + header.size :])


def _link_kind(raw: bytes) -> JsonValue:
    info = _attributes(raw)
    return _string(info[1]) if 1 in info else None  # IFLA_INFO_KIND


def _operstate(raw: bytes) -> JsonValue:
    return _indexed(raw[0], _OPERSTATES)


def _hex_id(raw: bytes) -> JsonValue:
    return raw.hex()


def _alt_names(raw: bytes) -> JsonValue:
    names: list[JsonValue] = [_string(v) for v in _all_attributes(raw, 53)]  # IFLA_ALT_IFNAME
    return names


_LINK_ATTRS: Mapping[str, _Attr] = MappingProxyType(
    {
        "name": _Attr(kind=3, decode=_string),
        "address": _Attr(kind=1, decode=_mac),
        "broadcast": _Attr(kind=2, decode=_mac),
        "permanent_address": _Attr(kind=54, decode=_mac),
        "mtu": _Attr(kind=4, decode=_u32),
        "min_mtu": _Attr(kind=50, decode=_u32),
        "max_mtu": _Attr(kind=51, decode=_u32),
        "tx_queue_len": _Attr(kind=13, decode=_u32),
        "num_tx_queues": _Attr(kind=31, decode=_u32),
        "num_rx_queues": _Attr(kind=32, decode=_u32),
        "gso_max_size": _Attr(kind=41, decode=_u32),
        "gso_max_segs": _Attr(kind=40, decode=_u32),
        "operstate": _Attr(kind=16, decode=_operstate),
        "qdisc": _Attr(kind=6, decode=_string),
        "alias": _Attr(kind=20, decode=_string),
        "group": _Attr(kind=27, decode=_u32),
        "link_index": _Attr(kind=5, decode=_u32),
        "master_index": _Attr(kind=10, decode=_u32),
        "kind": _Attr(kind=18, decode=_link_kind),
        "alt_names": _Attr(kind=52, decode=_alt_names),
        "parent_device": _Attr(kind=56, decode=_string),
        "parent_bus": _Attr(kind=57, decode=_string),
        "phys_port_name": _Attr(kind=38, decode=_string),
        "phys_port_id": _Attr(kind=34, decode=_hex_id),
        "phys_switch_id": _Attr(kind=36, decode=_hex_id),
    }
)


def decode_link(message: bytes) -> JsonObject:
    """Return one link (``RTM_NEWLINK``): index, name, addresses, MTU, queues, kind, parent device.

    Raises:
        ValueError: the message is cut short.
    """
    parts = _body(message, _IFINFO, "link")
    family, kind, index, flags, _ = parts.header
    data = parts.attributes
    del family
    return {
        "index": index,
        "type": hardware_type(kind),
        "flags": interface_flags(flags),
        **_fields(_attributes(data), _LINK_ATTRS),
    }


_ADDRESS_ATTRS: Mapping[str, _Attr] = MappingProxyType(
    {
        "address": _Attr(kind=1, decode=_ip),
        "local": _Attr(kind=2, decode=_ip),
        "label": _Attr(kind=3, decode=_string),
        "broadcast": _Attr(kind=4, decode=_ip),
    }
)


def decode_address(message: bytes) -> JsonObject:
    """Return one interface address (``RTM_NEWADDR``).

    Raises:
        ValueError: the message is cut short.
    """
    parts = _body(message, _IFADDR, "address")
    family, prefix, flags, scope, index = parts.header
    attrs = _attributes(parts.attributes)
    all_flags = _u32(attrs[_IFA_FLAGS]) if _IFA_FLAGS in attrs else flags  # IFA_FLAGS widens the 8-bit field
    return {
        "index": index,
        "family": _family(family),
        "prefix_length": prefix,
        "scope": _named(scope, _SCOPES),
        "flags": _flag_names(all_flags, _IFA_FLAG_NAMES),
        **_fields(attrs, _ADDRESS_ATTRS),
    }


def _prefix(attrs: Mapping[int, bytes], kind: int, length: int, family: int) -> str | None:
    if kind in attrs:
        return f"{_ip(attrs[kind])}/{length}"
    if length == 0 and family in {_AF_INET, _AF_INET6}:
        return "0.0.0.0/0" if family == _AF_INET else "::/0"
    return None


_ROUTE_ATTRS: Mapping[str, _Attr] = MappingProxyType(
    {
        "gateway": _Attr(kind=5, decode=_ip),
        "output_index": _Attr(kind=4, decode=_u32),
        "input_index": _Attr(kind=3, decode=_u32),
        "preferred_source": _Attr(kind=7, decode=_ip),
        "priority": _Attr(kind=6, decode=_u32),
    }
)


def decode_route(message: bytes) -> JsonObject:
    """Return one route (``RTM_NEWROUTE``), its table, protocol, scope and type by name.

    Raises:
        ValueError: the message is cut short.
    """
    parts = _body(message, _RTMSG, "route")
    family, dst_len, src_len, _, table, protocol, scope, kind, _ = parts.header
    attrs = _attributes(parts.attributes)
    table_id = _u32(attrs[_RTA_TABLE]) if _RTA_TABLE in attrs else table  # RTA_TABLE holds tables past 255
    return {
        "family": _family(family),
        "destination": _prefix(attrs, _RTA_DST, dst_len, family),
        "source": _prefix(attrs, _RTA_SRC, src_len, family) if src_len else None,
        "table": _named(table_id, _TABLES),
        "protocol": _named(protocol, _PROTOCOLS),
        "scope": _named(scope, _SCOPES),
        "type": _indexed(kind, _ROUTE_TYPES),
        **_fields(attrs, _ROUTE_ATTRS),
    }


def decode_neighbour(message: bytes) -> JsonObject:
    """Return one neighbour (``RTM_NEWNEIGH``): its address, link-layer address and state.

    Raises:
        ValueError: the message is cut short.
    """
    parts = _body(message, _NDMSG, "neighbour")
    family, index, state, _, _ = parts.header
    attrs = _attributes(parts.attributes)
    return {
        "index": index,
        "family": _family(family),
        "address": _ip(attrs[_NDA_DST]) if _NDA_DST in attrs else None,
        "link_address": _mac(attrs[_NDA_LLADDR]) if _NDA_LLADDR in attrs else None,
        "state": _flag_names(state, _NUD),
    }


__all__ = [
    "DumpKind",
    "decode_address",
    "decode_link",
    "decode_neighbour",
    "decode_route",
    "dump_request",
    "error_number",
    "hardware_type",
    "interface_flags",
    "is_done",
    "message_type",
    "split_messages",
]
