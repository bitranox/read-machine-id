"""What a device-mapper device is, read from the UUID its creator gave it.

Every tool that creates a device-mapper device stamps its UUID with a prefix naming itself:
cryptsetup writes ``CRYPT-<TYPE>-<volume uuid, 32 hex digits>-<name>`` (``LUKS1``, ``LUKS2``,
``PLAIN``...), LVM writes ``LVM-<volume group uuid><logical volume uuid>`` (32 characters each),
multipath writes ``mpath-<wwid>``. Linux shows it in ``/sys/block/dm-*/dm/uuid``; reading it needs
no privilege and no ioctl.

Contents:
    * :class:`DmKind` - crypt, lvm, multipath or other.
    * :class:`DmTarget` - what a UUID says.
    * :func:`classify_dm_uuid` - read one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject

_LVM_ID = 32
_HEX_UUID = 32
# Where the dashes of a canonical UUID go in its 32 hex digits.
_UUID_GROUPS = (8, 4, 4, 4, 12)


class DmKind(StrEnum):
    """Which tool made a device-mapper device."""

    CRYPT = "crypt"
    LVM = "lvm"
    MULTIPATH = "multipath"
    OTHER = "other"


@dataclass(frozen=True)
class DmTarget:
    """What a device-mapper UUID says: the kind, its subtype and the ids it carries."""

    kind: DmKind
    subtype: str | None = None
    volume_uuid: str | None = None
    group_uuid: str | None = None

    def as_json(self) -> JsonObject:
        """Return the target as JSON."""
        return {
            "kind": self.kind.value,
            "subtype": self.subtype,
            "volume_uuid": self.volume_uuid,
            "group_uuid": self.group_uuid,
        }


def _canonical(hex32: str) -> str:
    if len(hex32) != _HEX_UUID:
        return hex32
    parts: list[str] = []
    start = 0
    for size in _UUID_GROUPS:
        parts.append(hex32[start : start + size])
        start += size
    return "-".join(parts)


def _crypt(rest: str) -> DmTarget:
    subtype, _, tail = rest.partition("-")
    volume = tail.split("-", 1)[0] if tail else ""
    return DmTarget(DmKind.CRYPT, subtype=subtype or None, volume_uuid=_canonical(volume) if volume else None)


def classify_dm_uuid(uuid: str) -> DmTarget:
    """Return what a device-mapper UUID says about its device.

    Examples:
        >>> classify_dm_uuid("CRYPT-LUKS2-0123456789abcdef0123456789abcdef-luks-root").volume_uuid
        '01234567-89ab-cdef-0123-456789abcdef'
        >>> classify_dm_uuid("LVM-" + "a" * 32 + "b" * 32).group_uuid == "a" * 32
        True
        >>> classify_dm_uuid("").kind.value
        'other'
    """
    if uuid.startswith("CRYPT-"):
        return _crypt(uuid.removeprefix("CRYPT-"))
    if uuid.startswith("LVM-"):
        ids = uuid.removeprefix("LVM-")
        return DmTarget(DmKind.LVM, group_uuid=ids[:_LVM_ID] or None, volume_uuid=ids[_LVM_ID:] or None)
    if uuid.startswith("mpath-"):
        return DmTarget(DmKind.MULTIPATH, volume_uuid=uuid.removeprefix("mpath-") or None)
    return DmTarget(DmKind.OTHER)


__all__ = ["DmKind", "DmTarget", "classify_dm_uuid"]
