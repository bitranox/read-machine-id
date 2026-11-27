"""UEFI variables as Linux exposes them under ``/sys/firmware/efi/efivars``.

Each file is named ``<Name>-<vendor GUID>`` and holds the variable's 32-bit attributes followed by
its data. The variables read here are one-byte flags: Secure Boot on (``SecureBoot``), setup mode
(``SetupMode``), and shim's MOK state (``MokSBStateRT``: present when Secure Boot validation was
turned off in shim).

Contents:
    * :class:`FirmwareType` - UEFI or BIOS.
    * :data:`EFI_GLOBAL`, :data:`SHIM_LOCK` - the vendor GUIDs.
    * :func:`efivar_path` - the file a variable sits in.
    * :func:`decode_efivar_flag` - a one-byte flag variable.
"""

from __future__ import annotations

from enum import StrEnum


class FirmwareType(StrEnum):
    """How the machine booted, spelled as Windows reports it."""

    UEFI = "UEFI"
    BIOS = "BIOS"


#: The UEFI global variable vendor GUID (SecureBoot, SetupMode).
EFI_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#: shim's vendor GUID (MokSBStateRT and the other MOK variables).
SHIM_LOCK = "605dab50-e046-4300-abb6-3dd810dd8b23"
EFIVARS = "/sys/firmware/efi/efivars"
_ATTRIBUTES = 4


def efivar_path(name: str, guid: str) -> str:
    """Return the path of one variable.

    Example:
        >>> efivar_path("SecureBoot", EFI_GLOBAL)
        '/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
    """
    return f"{EFIVARS}/{name}-{guid}"


def decode_efivar_flag(raw: bytes) -> bool:
    """Return a one-byte flag variable: True when its first data byte is 1.

    Raises:
        ValueError: the file holds the attributes and no data.

    Example:
        >>> decode_efivar_flag(b"\\x06\\0\\0\\0\\x01")
        True
    """
    if len(raw) <= _ATTRIBUTES:
        msg = f"efivar holds {len(raw)} bytes, no data after its 4-byte attributes"
        raise ValueError(msg)
    return raw[_ATTRIBUTES] == 1


__all__ = ["EFIVARS", "EFI_GLOBAL", "SHIM_LOCK", "FirmwareType", "decode_efivar_flag", "efivar_path"]
