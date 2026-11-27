"""The firmware tables, the firmware type and the TPM device info, asked through ctypes.

These come from kernel32 (``EnumSystemFirmwareTables``, ``GetSystemFirmwareTable``,
``GetFirmwareType``) and tbs.dll (``Tbsi_GetDeviceInfo``) rather than WMI: the raw SMBIOS block
and the ACPI tables are what the firmware handed Windows, and TBS answers for the TPM without the
administrator rights the ``Win32_Tpm`` WMI class needs.

Off Windows every function raises :class:`SourceError`; the module still imports, so the
package installs and its other commands run everywhere.

Contents:
    * :func:`firmware_table` - one firmware table.
    * :func:`firmware_table_ids` - the ids of every table a provider exposes.
    * :func:`firmware_type` - UEFI or BIOS.
    * :func:`tbs_device_info` - the raw TPM_DEVICE_INFO structure.
"""

from __future__ import annotations

import ctypes
import sys

from ...domain.machine_errors import SourceError

#: Provider signatures as GetSystemFirmwareTable takes them (the four characters, big-endian).
RSMB = int.from_bytes(b"RSMB", "big")
ACPI = int.from_bytes(b"ACPI", "big")

_FIRMWARE_TYPES = {1: "BIOS", 2: "UEFI"}
# TPM_DEVICE_INFO is four u32 fields.
_TBS_DEVICE_INFO_SIZE = 16
_TBS_SUCCESS = 0
_ID_BYTES = 4


def _not_windows() -> SourceError:
    return SourceError(f"firmware tables need Windows, this is {sys.platform}")


def _call_sized(fetch: object, *args: int) -> bytes:
    """Call a ``(..., buffer, size) -> needed`` API twice: once for the size, once for the data."""
    if not callable(fetch):
        raise _not_windows()
    needed = int(fetch(*args, None, 0))
    if needed == 0:
        raise SourceError(f"firmware table call failed, Windows error {ctypes.get_last_error()}")
    buffer = ctypes.create_string_buffer(needed)
    written = int(fetch(*args, buffer, needed))
    if written != needed:
        raise SourceError(f"firmware table changed size while being read ({needed} -> {written} bytes)")
    return buffer.raw[:written]


def firmware_table(provider: int, table_id: int) -> bytes:
    """Return one firmware table (``RSMB``: the whole SMBIOS block, table id 0).

    Raises:
        SourceError: not on Windows, or Windows refused.
    """
    if sys.platform != "win32":
        raise _not_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return _call_sized(kernel32.GetSystemFirmwareTable, provider, table_id)


def firmware_table_ids(provider: int) -> list[int]:
    """Return the ids of every table ``provider`` exposes, each once, in firmware order.

    Raises:
        SourceError: not on Windows, or Windows refused.
    """
    if sys.platform != "win32":
        raise _not_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    raw = _call_sized(kernel32.EnumSystemFirmwareTables, provider)
    ids = [int.from_bytes(raw[i : i + _ID_BYTES], "little") for i in range(0, len(raw), _ID_BYTES)]
    # Several tables can share one signature (SSDT); the API returns only the first of them.
    return list(dict.fromkeys(ids))


def firmware_type() -> str:
    """Return ``"UEFI"``, ``"BIOS"`` or ``"unknown(<n>)"``.

    Raises:
        SourceError: not on Windows, or the call failed.
    """
    if sys.platform != "win32":
        raise _not_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    value = ctypes.c_uint(0)
    if not kernel32.GetFirmwareType(ctypes.byref(value)):
        raise SourceError(f"GetFirmwareType failed, Windows error {ctypes.get_last_error()}")
    return _FIRMWARE_TYPES.get(value.value, f"unknown({value.value})")


def tbs_device_info() -> bytes:
    """Return the TPM_DEVICE_INFO structure TBS fills.

    Raises:
        SourceError: not on Windows, no TPM (TBS_E_TPM_NOT_FOUND), or TBS refused.
    """
    if sys.platform != "win32":
        raise _not_windows()
    try:
        tbs = ctypes.WinDLL("tbs")
    except OSError as exc:
        raise SourceError(f"tbs.dll not loadable: {exc}") from exc
    buffer = ctypes.create_string_buffer(_TBS_DEVICE_INFO_SIZE)
    result = int(tbs.Tbsi_GetDeviceInfo(_TBS_DEVICE_INFO_SIZE, buffer)) & 0xFFFFFFFF
    if result != _TBS_SUCCESS:
        raise SourceError(f"Tbsi_GetDeviceInfo returned 0x{result:08X}")
    return buffer.raw


__all__ = ["ACPI", "RSMB", "firmware_table", "firmware_table_ids", "firmware_type", "tbs_device_info"]
