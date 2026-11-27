"""A recorded machine: its sources answered from a JSON document (and, for Linux, a directory).

Tests drive the whole collection through this, on every OS, and it can replay a machine whose
answers were saved. A recorded Windows machine is one document::

    {
      "cim":      {"<namespace>:<Class>": [ {property: value, ...}, ... ]},
      "registry": {"<KEY PATH>": {"values": {name: data}, "subkeys": [name, ...]}},
      "firmware": {"smbios_hex": "...", "smbios_version": "3.1",
                   "acpi_hex": ["...", ...], "tbs_hex": "...", "firmware_type": "UEFI"},
      "cpuid":    {"0x<leaf>:<subleaf>": {"eax": "0x...", "ebx": ..., "ecx": ..., "edx": ...}}
    }

A registry value written as ``{"hex": "0a0b"}`` is binary data. Key paths compare
case-insensitively, as Windows does. A class, key or firmware entry the document lacks answers
:class:`SourceError`, exactly like a class that does not exist on a real machine. A ``where``
filter is not evaluated: a recording holds the rows the query returned.

The ``cpuid`` block uses the keys and register form of a reading's ``cpuid.raw``, so a reading
replays as a recording. A leaf it lacks answers four zero registers, as a CPU answers a leaf it
does not implement; one recorded as ``{"error": "..."}`` raises :class:`SourceError`.

A recorded Linux machine is a directory that mirrors ``/`` (``sys/``, ``proc/``, ``etc/``,
``run/``) plus a document for what is not a file::

    {
      "cpuid":   {...as above...},
      "ethtool": {"<ifname>": {"<request hex>": "<answer hex>"}},
      "netlink": {"<links|addresses|routes|neighbours>": ["<message hex>", ...]},
      "tpm_nv":  {"0x<index, 8 hex digits>": "<content hex>"}
    }

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

from ..domain.cpuid import CpuidQuery, CpuidRegs
from ..domain.machine_errors import MissingKeyError, NotAReadingError, SourceError
from .linux.sysfs import FilesystemReader

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from ..application.machine_ports import NetlinkDump, RegistryData
    from ..domain.json_types import JsonObject, JsonValue


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


def _recorded_cpuid(recorded: JsonObject, leaf: int, subleaf: int) -> CpuidRegs:
    """The recorded answer to one CPUID question: zeros when unrecorded, an error when recorded so."""
    answer = recorded.get(CpuidQuery(leaf, subleaf).key)
    if answer is None:
        return CpuidRegs(eax=0, ebx=0, ecx=0, edx=0)
    regs = _obj(answer, f"cpuid {CpuidQuery(leaf, subleaf).key}")
    if isinstance(error := regs.get("error"), str):
        raise SourceError(error)
    return CpuidRegs(*(_register(regs, r) for r in ("eax", "ebx", "ecx", "edx")))


class FixtureSources:
    """Both sources of one recorded machine."""

    def __init__(self, document: JsonObject) -> None:
        """Hold ``document`` (see the module docstring for its shape)."""
        self._cim = _obj(document.get("cim", {}), "cim")
        self._firmware = _obj(document.get("firmware", {}), "firmware")
        self._cpuid = _obj(document.get("cpuid", {}), "cpuid")
        registry = _obj(document.get("registry", {}), "registry")
        self._keys = {path.casefold(): _obj(entry, path) for path, entry in registry.items()}

    # PlatformSource -------------------------------------------------------------------------

    def cim(self, class_name: str, *, namespace: str = "root/cimv2", where: str | None = None) -> list[JsonObject]:
        """Return the recorded rows of ``namespace:class_name``."""
        del where
        rows = self._cim.get(f"{namespace}:{class_name}")
        if not isinstance(rows, list):
            raise SourceError(f"{namespace}:{class_name}: not recorded")
        return [r for r in rows if isinstance(r, dict)]

    def _hex(self, name: str) -> bytes:
        text = self._firmware.get(name)
        if not isinstance(text, str):
            raise SourceError(f"firmware.{name}: not recorded")
        return bytes.fromhex(text)

    def smbios_table(self) -> tuple[bytes, str]:
        """Return the recorded SMBIOS table and version."""
        return self._hex("smbios_hex"), str(self._firmware.get("smbios_version", "0.0"))

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

    def netlink_dump(self, table: NetlinkDump) -> list[bytes]:
        """Return the recorded messages of one rtnetlink dump."""
        messages = self._netlink.get(table.value)
        if not isinstance(messages, list):
            raise SourceError(f"netlink {table.value}: not recorded")
        return [bytes.fromhex(m) for m in messages if isinstance(m, str)]

    def tpm_nv_read(self, index: int) -> bytes:
        """Return the recorded content of one TPM NV index."""
        content = self._tpm_nv.get(f"0x{index:08x}")
        if not isinstance(content, str):
            raise SourceError(f"tpm nv index 0x{index:08x}: not recorded")
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
