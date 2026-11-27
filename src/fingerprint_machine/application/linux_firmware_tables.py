"""The ``smbios`` and ``acpi`` sections of a Linux reading: the firmware's own tables.

SMBIOS: Linux exposes the raw structure table (``/sys/firmware/dmi/tables/DMI``) and its entry
point; both are root-only. Decoded by the same :func:`decode_smbios` as on Windows, so
``smbios.system`` has the same shape on both OSes. Next to it, always, the kernel's decoded
copy under ``/sys/class/dmi/id``: most files there are world-readable, the serials and the UUID
are root-only, so an unprivileged reading still names vendor, product and BIOS.

ACPI: every table file under ``/sys/firmware/acpi/tables`` (the runtime-loaded ``dynamic/`` ones
too; ``data/`` holds error-record payloads, not tables) is listed by anyone and read by root; its
header is decoded as on Windows. MSDM is reported only as present with the product key masked to
its last five characters.

Contents:
    * :data:`DMI_ID_FILES` - the files the kernel offers under ``/sys/class/dmi/id``.
    * :func:`dmi_id_values` - those files, each guarded.
    * :func:`read_linux_smbios` - the ``smbios`` section.
    * :func:`read_linux_acpi` - the ``acpi`` section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.identity import decode_acpi_header, msdm_product_key
from ..domain.smbios import decode_smbios
from ..domain.smbios_entry import decode_smbios_entry_point
from .guard import guarded
from .linux_files import file_values, item_section, optional_dir

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

_DMI_TABLES = "/sys/firmware/dmi/tables"
_DMI_ID = "/sys/class/dmi/id"
_ACPI = "/sys/firmware/acpi/tables"
_ENTRY_POINT_MAX = 64  # an entry point is 24 (_SM3_) or 31 (_SM_) bytes
_ACPI_DYNAMIC = "dynamic"
_ACPI_DATA = "data"

#: The attributes drivers/firmware/dmi-id.c defines (product_serial, product_uuid, board_serial,
#: chassis_serial need root), less ``modalias``: it repeats them all in one line, and the
#: ``platform`` section records it as ``dmi_modalias``.
DMI_ID_FILES = (
    "bios_date",
    "bios_release",
    "bios_vendor",
    "bios_version",
    "board_asset_tag",
    "board_name",
    "board_serial",
    "board_vendor",
    "board_version",
    "chassis_asset_tag",
    "chassis_serial",
    "chassis_type",
    "chassis_vendor",
    "chassis_version",
    "ec_firmware_release",
    "product_family",
    "product_name",
    "product_serial",
    "product_sku",
    "product_uuid",
    "product_version",
    "sys_vendor",
)


def dmi_id_values(src: LinuxSource) -> JsonObject:
    """Return every ``/sys/class/dmi/id`` attribute this kernel offers, each guarded."""
    return file_values(src, _DMI_ID, DMI_ID_FILES)


def _entry_point(src: LinuxSource) -> JsonValue:
    raw = src.read_bytes(f"{_DMI_TABLES}/smbios_entry_point", max_bytes=_ENTRY_POINT_MAX)
    return decode_smbios_entry_point(raw).as_json()


def _decoded_table(src: LinuxSource, entry: JsonValue) -> JsonValue:
    version = entry.get("version") if isinstance(entry, dict) else None
    table = src.read_bytes(f"{_DMI_TABLES}/DMI")
    return decode_smbios(table, version if isinstance(version, str) else "unknown")


def read_linux_smbios(src: LinuxSources) -> JsonValue:
    """Read the ``smbios`` section: the decoded table (as root), its entry point and ``dmi_id``.

    The decoded table's keys sit at the top, as on Windows; when the table cannot be read, its
    error sits under ``table`` instead.
    """
    system = src.system
    entry = guarded(lambda: _entry_point(system))
    decoded = guarded(lambda: _decoded_table(system, entry))
    body: JsonObject = decoded if isinstance(decoded, dict) and "error" not in decoded else {"table": decoded}
    return {**body, "entry_point": entry, "dmi_id": dmi_id_values(system)}


def _table_files(src: LinuxSource) -> Iterator[str]:
    for name in src.list_dir(_ACPI):
        if name == _ACPI_DATA:
            continue
        if name == _ACPI_DYNAMIC:
            yield from (f"{_ACPI_DYNAMIC}/{sub}" for sub in optional_dir(src, f"{_ACPI}/{_ACPI_DYNAMIC}"))
        else:
            yield name


def _table_header(src: LinuxSource, name: str) -> JsonObject:
    header = guarded(lambda: decode_acpi_header(src.read_bytes(f"{_ACPI}/{name}")))
    return {"file": name, **(header if isinstance(header, dict) else {"value": header})}


def _acpi_tables(src: LinuxSources) -> JsonValue:
    # One table read at a time: the DSDT alone can be a megabyte.
    headers: list[JsonValue] = [_table_header(src.system, name) for name in _table_files(src.system)]
    return headers


def _msdm(src: LinuxSources) -> JsonValue:
    if "MSDM" not in src.system.list_dir(_ACPI):
        return {"present": False, "product_key": None}
    return msdm_product_key(src.system.read_bytes(f"{_ACPI}/MSDM"))


def read_linux_acpi(src: LinuxSources) -> JsonValue:
    """Read the ``acpi`` section: every table's header, and MSDM with its key masked."""
    return item_section(src, {"tables": _acpi_tables, "msdm": _msdm})


__all__ = ["DMI_ID_FILES", "dmi_id_values", "read_linux_acpi", "read_linux_smbios"]
