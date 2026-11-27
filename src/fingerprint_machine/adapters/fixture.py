"""A recorded machine: its sources answered from a JSON document (and, for Linux, a directory).

Tests drive the whole collection through this, on every OS, and it can replay a machine whose
answers were saved. A recorded Windows machine is one document::

    {
      "cim":      {"<namespace>:<Class>": [ {property: value, ...}, ... ]},
      "cim_methods": {"<namespace>:<Class>.<Method>": [
                    {"where": "<WQL or null>", "arguments": {name: value} or null,
                     "instance_path": "...", "return_value": 0, "out": {name: value}}, ...]},
      "registry": {"<KEY PATH>": {"values": {name: data}, "subkeys": [name, ...]}},
      "firmware": {"smbios_hex": "...", "smbios_version": "3.1",
                   "acpi_hex": ["...", ...], "tbs_hex": "...", "firmware_type": "UEFI"},
      "cpuid":    {"0x<leaf>:<subleaf>": {"eax": "0x...", "ebx": ..., "ecx": ..., "edx": ...}},
      "device_properties": {"<instance id>": {"<DeviceProperty value>": <decoded value>}},
      "system":   {"numa_nodes": [{"node": 0, "group": 0, "mask": "0xf"}],
                   "kernel_dma_protection": false}
    }

A registry value written as ``{"hex": "0a0b"}`` is binary data. Key paths and instance ids
compare case-insensitively, as Windows does; a device property the document lacks is one the
device does not have (:class:`MissingKeyError`). A class, key or firmware entry the document lacks answers
:class:`SourceError`, exactly like a class that does not exist on a real machine. A ``where``
filter is not evaluated: a recording holds the rows the query returned. A method call answers the
``cim_methods`` entries recorded with the same ``where`` and ``arguments`` (a missing field means
none), so one recording can hold a different answer per volume and per argument; a method the
document lacks answers :class:`SourceError`.

The ``cpuid`` block uses the keys and register form of a reading's ``cpuid.raw``, so a reading
replays as a recording. A leaf it lacks answers four zero registers, as a CPU answers a leaf it
does not implement; one recorded as ``{"error": "..."}`` raises :class:`SourceError`.

A recorded Linux machine is a directory that mirrors ``/`` (``sys/``, ``proc/``, ``etc/``,
``run/``) plus a document for what is not a file::

    {
      "cpuid":   {...as above...},
      "ethtool": {"<ifname>": {"<request hex>": "<answer hex>"}},
      "netlink": {"<links|addresses|routes|neighbours>": ["<message hex>", ...]},
      "tpm_nv":  {"0x<index, 8 hex digits>": "<content hex>"},
      "links":   {"<absolute path>": "<link target, as the link writes it>"}
    }

A TPM NV index the ``tpm_nv`` block lacks answers as a TPM answers an index it does not define
(:class:`TpmResponseError` ``0x18b``).

``links`` stands in for the symbolic links sysfs is full of, so a recorded tree can use plain
directories (a Windows test run may not create links); a path it does not name is read as a real
link under the root.

Contents:
    * :class:`FixtureSources` - :class:`PlatformSource`, :class:`RegistrySource` and
      :class:`CpuidSource` from a document.
    * :class:`FixtureLinuxSource` - :class:`LinuxSource` and :class:`CpuidSource` from a
      directory and a document.
    * :func:`load_fixture` - read a Windows document from a file.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from ..domain.cim_method import CimMethodAnswer
from ..domain.cpuid import CpuidQuery, CpuidRegs
from ..domain.machine_errors import MissingKeyError, NotAReadingError, SourceError
from ..domain.numa import NumaNode
from ..domain.smbios import RawSmbios
from ..domain.tpm2 import TpmResponseError
from .linux.sysfs import FilesystemReader

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from pathlib import Path

    from ..application.machine_ports import NetlinkDump, RegistryData
    from ..domain.cim_method import CimArgument
    from ..domain.devprops import DeviceProperty
    from ..domain.json_types import JsonObject, JsonValue

# What a TPM answers NV_ReadPublic of an index it does not define: TPM_RC_HANDLE on handle 1.
_TPM_RC_UNDEFINED_INDEX = 0x18B


def _obj(value: JsonValue, where: str) -> JsonObject:
    if not isinstance(value, dict):
        raise SourceError(f"{where}: not recorded")
    return value


def _registry_data(value: JsonValue) -> RegistryData:
    if isinstance(value, dict) and isinstance(hex_text := value.get("hex"), str):
        return bytes.fromhex(hex_text)
    if isinstance(value, list):
        return [str(v) for v in value]
    if value is None or isinstance(value, (int, str)):
        return value
    return str(value)


def _register(regs: JsonObject, name: str) -> int:
    value = regs.get(name)
    if isinstance(value, str):
        return int(value, 16)
    if isinstance(value, int):
        return value
    raise SourceError(f"cpuid register {name}: not recorded")


def _numa_node(node: JsonObject) -> NumaNode:
    number, group, mask = node.get("node"), node.get("group"), node.get("mask")
    if not isinstance(number, int) or not isinstance(group, int) or not isinstance(mask, str):
        raise SourceError(f"system.numa_nodes: {node} is not a recorded node")
    return NumaNode(node=number, group=group, mask=int(mask, 16))


def _recorded_cpuid(recorded: JsonObject, leaf: int, subleaf: int) -> CpuidRegs:
    """The recorded answer to one CPUID question: zeros when unrecorded, an error when recorded so."""
    answer = recorded.get(CpuidQuery(leaf, subleaf).key)
    if answer is None:
        return CpuidRegs(eax=0, ebx=0, ecx=0, edx=0)
    regs = _obj(answer, f"cpuid {CpuidQuery(leaf, subleaf).key}")
    if isinstance(error := regs.get("error"), str):
        raise SourceError(error)
    return CpuidRegs(*(_register(regs, r) for r in ("eax", "ebx", "ecx", "edx")))


def _method_answer(entry: JsonObject, where: str) -> CimMethodAnswer:
    path, value = entry.get("instance_path"), entry.get("return_value")
    if not isinstance(path, str) or not (value is None or isinstance(value, int)):
        raise SourceError(f"{where}: {entry} is not a recorded method answer")
    return CimMethodAnswer(instance_path=path, return_value=value, out=_obj(entry.get("out", {}), where))


def _same_call(entry: JsonObject, where: str | None, arguments: Mapping[str, CimArgument] | None) -> bool:
    recorded = entry.get("arguments") or {}
    return entry.get("where") == where and recorded == dict(arguments or {})


class FixtureSources:
    """Both sources of one recorded machine."""

    def __init__(self, document: JsonObject) -> None:
        """Hold ``document`` (see the module docstring for its shape)."""
        self._cim = _obj(document.get("cim", {}), "cim")
        self._methods = _obj(document.get("cim_methods", {}), "cim_methods")
        self._firmware = _obj(document.get("firmware", {}), "firmware")
        self._cpuid = _obj(document.get("cpuid", {}), "cpuid")
        self._system = _obj(document.get("system", {}), "system")
        registry = _obj(document.get("registry", {}), "registry")
        self._keys = {path.casefold(): _obj(entry, path) for path, entry in registry.items()}
        properties = _obj(document.get("device_properties", {}), "device_properties")
        self._properties = {i.casefold(): _obj(p, i) for i, p in properties.items()}

    # PlatformSource -------------------------------------------------------------------------

    def cim(self, class_name: str, *, namespace: str = "root/cimv2", where: str | None = None) -> list[JsonObject]:
        """Return the recorded rows of ``namespace:class_name``."""
        del where
        rows = self._cim.get(f"{namespace}:{class_name}")
        if not isinstance(rows, list):
            raise SourceError(f"{namespace}:{class_name}: not recorded")
        return [r for r in rows if isinstance(r, dict)]

    def cim_method(
        self,
        class_name: str,
        method_name: str,
        *,
        namespace: str = "root/cimv2",
        where: str | None = None,
        arguments: Mapping[str, CimArgument] | None = None,
    ) -> list[CimMethodAnswer]:
        """Return the recorded answers of ``namespace:class_name.method_name`` for this call."""
        key = f"{namespace}:{class_name}.{method_name}"
        entries = self._methods.get(key)
        if not isinstance(entries, list):
            raise SourceError(f"{key}: not recorded")
        recorded = [e for e in entries if isinstance(e, dict)]
        return [_method_answer(e, key) for e in recorded if _same_call(e, where, arguments)]

    def _hex(self, name: str) -> bytes:
        text = self._firmware.get(name)
        if not isinstance(text, str):
            raise SourceError(f"firmware.{name}: not recorded")
        return bytes.fromhex(text)

    def smbios_table(self) -> RawSmbios:
        """Return the recorded SMBIOS table and version."""
        return RawSmbios(table=self._hex("smbios_hex"), version=str(self._firmware.get("smbios_version", "0.0")))

    def acpi_tables(self) -> list[bytes]:
        """Return the recorded ACPI tables."""
        tables = self._firmware.get("acpi_hex")
        if not isinstance(tables, list):
            raise SourceError("firmware.acpi_hex: not recorded")
        return [bytes.fromhex(t) for t in tables if isinstance(t, str)]

    def tbs_device_info(self) -> bytes:
        """Return the recorded TPM_DEVICE_INFO."""
        return self._hex("tbs_hex")

    def firmware_type(self) -> str:
        """Return the recorded firmware type."""
        value = self._firmware.get("firmware_type")
        if not isinstance(value, str):
            raise SourceError("firmware.firmware_type: not recorded")
        return value

    def device_property(self, instance_id: str, prop: DeviceProperty) -> JsonValue:
        """Return the recorded property of a device; an unrecorded device or property is not set."""
        recorded = self._properties.get(instance_id.casefold())
        if recorded is None or prop.value not in recorded:
            raise MissingKeyError(f"{instance_id}: no {prop.value} property")
        return recorded[prop.value]

    def numa_nodes(self) -> list[NumaNode]:
        """Return the recorded NUMA nodes."""
        nodes = self._system.get("numa_nodes")
        if not isinstance(nodes, list):
            raise SourceError("system.numa_nodes: not recorded")
        return [_numa_node(_obj(n, "system.numa_nodes")) for n in nodes]

    def kernel_dma_protection(self) -> bool:
        """Return the recorded Kernel DMA Protection state."""
        value = self._system.get("kernel_dma_protection")
        if not isinstance(value, bool):
            raise SourceError("system.kernel_dma_protection: not recorded")
        return value

    # CpuidSource ----------------------------------------------------------------------------

    def cpuid(self, leaf: int, *, subleaf: int = 0) -> CpuidRegs:
        """Return the recorded registers of one leaf (zeros when unrecorded)."""
        return _recorded_cpuid(self._cpuid, leaf, subleaf)

    # RegistrySource -------------------------------------------------------------------------

    def _key(self, key: str) -> JsonObject:
        entry = self._keys.get(key.casefold())
        if entry is None:
            raise MissingKeyError(f"{key}: key not found")
        return entry

    def values(self, key: str) -> dict[str, RegistryData]:
        """Return the recorded values of ``key``."""
        values = self._key(key).get("values", {})
        return {name: _registry_data(data) for name, data in _obj(values, key).items()}

    def subkeys(self, key: str) -> list[str]:
        """Return the recorded subkeys of ``key``, sorted case-insensitively."""
        names = self._key(key).get("subkeys", [])
        return sorted((str(n) for n in names) if isinstance(names, list) else [], key=str.casefold)


class FixtureLinuxSource(FilesystemReader):
    """A recorded Linux machine: files under ``root``, everything else from ``answers``."""

    def __init__(self, root: Path, answers: Mapping[str, JsonValue]) -> None:
        """Read the machine's ``/`` at ``root`` and its kernel interfaces from ``answers``."""
        super().__init__(root)
        self._cpuid = _obj(answers.get("cpuid", {}), "cpuid")
        self._ethtool = _obj(answers.get("ethtool", {}), "ethtool")
        self._netlink = _obj(answers.get("netlink", {}), "netlink")
        self._tpm_nv = _obj(answers.get("tpm_nv", {}), "tpm_nv")
        self._links = _obj(answers.get("links", {}), "links")

    def cpuid(self, leaf: int, *, subleaf: int = 0) -> CpuidRegs:
        """Return the recorded registers of one leaf (zeros when unrecorded)."""
        return _recorded_cpuid(self._cpuid, leaf, subleaf)

    def ethtool(self, ifname: str, *, request: bytes) -> bytes:
        """Return the recorded answer to one ethtool request on ``ifname``."""
        answers = _obj(self._ethtool.get(ifname), f"ethtool {ifname}")
        answer = answers.get(request.hex())
        if not isinstance(answer, str):
            raise SourceError(f"ethtool {ifname} {request.hex()}: not recorded")
        return bytes.fromhex(answer)

    def netlink_dump(self, table: NetlinkDump) -> Iterator[bytes]:
        """Return the recorded messages of one rtnetlink dump."""
        messages = self._netlink.get(table.value)
        if not isinstance(messages, list):
            raise SourceError(f"netlink {table.value}: not recorded")
        return iter([bytes.fromhex(m) for m in messages if isinstance(m, str)])

    def readlink(self, path: str) -> str:
        """Return the recorded target of a link, else the target of a real link under the root."""
        target = self._links.get(path)
        return target if isinstance(target, str) else super().readlink(path)

    def tpm_nv_read(self, index: int) -> bytes:
        """Return the recorded content of one TPM NV index; an unrecorded one is not defined."""
        content = self._tpm_nv.get(f"0x{index:08x}")
        if content is None:
            raise TpmResponseError(_TPM_RC_UNDEFINED_INDEX)
        if not isinstance(content, str):
            raise SourceError(f"tpm nv index 0x{index:08x}: not recorded as hex")
        return bytes.fromhex(content)


def load_fixture(path: Path) -> FixtureSources:
    """Read a recorded machine from ``path``.

    Raises:
        NotAReadingError: the file cannot be read or is not a JSON object.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NotAReadingError(f"{path}: {exc}") from exc
    if not isinstance(document, dict):
        raise NotAReadingError(f"{path}: not a JSON object")
    return FixtureSources(cast("JsonObject", document))


__all__ = ["FixtureLinuxSource", "FixtureSources", "load_fixture"]
