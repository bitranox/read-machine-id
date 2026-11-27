"""The sections a reading can hold, on either OS.

Contents:
    * :class:`Section` - the section names, in document order after ``meta`` and ``summary``.
"""

from __future__ import annotations

from enum import StrEnum


class Section(StrEnum):
    """The sections of a reading, in document order after ``meta`` and ``summary``.

    Windows reads all of them; Linux reads the ones its collector lists and records an error for
    the rest.
    """

    SMBIOS = "smbios"
    ACPI = "acpi"
    PLATFORM = "platform"
    CPU = "cpu"
    CPUID = "cpuid"
    MEMORY = "memory"
    DISKS = "disks"
    NETWORK = "network"
    HARDWARE = "hardware"
    DEVICES = "devices"
    WINDOWS = "windows"
    SECURITY = "security"
    SERVICES = "services"


__all__ = ["Section"]
