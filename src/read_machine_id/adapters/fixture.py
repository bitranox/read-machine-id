"""A recorded machine: both sources answered from one JSON document.

Tests drive the whole collection through this, on every OS, and it can replay a machine whose
answers were saved. The document holds::

    {
      "cim":      {"<namespace>:<Class>": [ {property: value, ...}, ... ]},
      "registry": {"<KEY PATH>": {"values": {name: data}, "subkeys": [name, ...]}},
      "firmware": {"smbios_hex": "...", "smbios_version": "3.1",
                   "acpi_hex": ["...", ...], "tbs_hex": "...", "firmware_type": "UEFI"}
    }

A registry value written as ``{"hex": "0a0b"}`` is binary data. Key paths compare
case-insensitively, as Windows does. A class, key or firmware entry the document lacks answers
:class:`SourceError`, exactly like a class that does not exist on a real machine. A ``where``
filter is not evaluated: a recording holds the rows the query returned.

Contents:
    * :class:`FixtureSources` - :class:`PlatformSource` and :class:`RegistrySource` from a document.
    * :func:`load_fixture` - read a document from a file.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from ..domain.machine_errors import NotAReadingError, SourceError

if TYPE_CHECKING:
    from pathlib import Path

    from ..application.machine_ports import RegistryData
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


class FixtureSources:
    """Both sources of one recorded machine."""

    def __init__(self, document: JsonObject) -> None:
        """Hold ``document`` (see the module docstring for its shape)."""
        self._cim = _obj(document.get("cim", {}), "cim")
        self._firmware = _obj(document.get("firmware", {}), "firmware")
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

    # RegistrySource -------------------------------------------------------------------------

    def _key(self, key: str) -> JsonObject:
        entry = self._keys.get(key.casefold())
        if entry is None:
            raise SourceError(f"{key}: key not found")
        return entry

    def values(self, key: str) -> dict[str, RegistryData]:
        """Return the recorded values of ``key``."""
        values = self._key(key).get("values", {})
        return {name: _registry_data(data) for name, data in _obj(values, key).items()}

    def subkeys(self, key: str) -> list[str]:
        """Return the recorded subkeys of ``key``, sorted case-insensitively."""
        names = self._key(key).get("subkeys", [])
        return sorted((str(n) for n in names) if isinstance(names, list) else [], key=str.casefold)


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


__all__ = ["FixtureSources", "load_fixture"]
