"""The standard SCSI INQUIRY data a disk answers with: its type, vendor, product and revision.

Windows keeps each logical unit's INQUIRY answer in the registry (``HARDWARE\\DEVICEMAP\\Scsi``,
value ``InquiryData``); Linux shows the same fields as sysfs attributes of the SCSI device
(``vendor``, ``model``, ``rev``, ``type``). The decoded answer uses the Linux names, so the disks
of a Windows and a Linux reading of one machine line up (SPC-5, 6.7.2 "Standard INQUIRY data").

Contents:
    * :class:`Inquiry`, :func:`decode_inquiry` - the decoded answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject

#: Vendor (8 bytes), product (16) and revision (4) end at byte 36.
_MINIMUM_BYTES = 36
_TYPE_BITS = 0x1F
_QUALIFIER_SHIFT = 5
_REMOVABLE = 0x80


def _ascii(data: bytes) -> str:
    return data.decode("ascii", errors="replace").strip()


@dataclass(frozen=True, slots=True)
class Inquiry:
    """The identity fields of a standard INQUIRY answer."""

    #: The peripheral device type (0 a disk, 5 a CD/DVD drive, 0x0D an enclosure).
    type: int
    #: The peripheral qualifier (0: a device of that type is connected to this unit).
    qualifier: int
    removable: bool
    #: The SPC version the device claims.
    version: int
    vendor: str
    model: str
    rev: str

    def as_json(self) -> JsonObject:
        """Return the answer under the names a Linux reading uses."""
        return {
            "type": self.type,
            "qualifier": self.qualifier,
            "removable": self.removable,
            "version": self.version,
            "vendor": self.vendor,
            "model": self.model,
            "rev": self.rev,
        }


def decode_inquiry(data: bytes) -> Inquiry:
    """Decode a standard INQUIRY answer.

    Raises:
        ValueError: ``data`` is shorter than the 36 bytes the identity fields need.

    Example:
        >>> answer = bytes([0, 0, 6, 2, 31, 0, 0, 0]) + b"VMware  Virtual disk    2.0 "
        >>> decode_inquiry(answer).as_json()["model"], decode_inquiry(answer).vendor
        ('Virtual disk', 'VMware')
    """
    if len(data) < _MINIMUM_BYTES:
        raise ValueError(f"an INQUIRY answer has at least {_MINIMUM_BYTES} bytes, got {len(data)}")
    return Inquiry(
        type=data[0] & _TYPE_BITS,
        qualifier=data[0] >> _QUALIFIER_SHIFT,
        removable=bool(data[1] & _REMOVABLE),
        version=data[2],
        vendor=_ascii(data[8:16]),
        model=_ascii(data[16:32]),
        rev=_ascii(data[32:36]),
    )


__all__ = ["Inquiry", "decode_inquiry"]
