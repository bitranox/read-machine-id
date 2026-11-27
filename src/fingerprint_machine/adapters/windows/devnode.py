"""Device properties from the configuration manager (cfgmgr32), asked through ctypes.

A device's parent, location paths, bus number and the PCI driver's link and interrupt
properties are in no WMI class, and the registry key Windows stores them in belongs to SYSTEM.
``CM_Get_DevNode_PropertyW`` answers them for any caller. The device is located with
``CM_LOCATE_DEVNODE_PHANTOM`` so a device seen before but absent now still answers what
Windows stored for it.

Off Windows :func:`device_property` raises :class:`SourceError`; the module still imports.

Contents:
    * :func:`device_property` - one property of one device instance.
"""

from __future__ import annotations

import ctypes
import sys
import uuid
from ctypes import wintypes
from typing import TYPE_CHECKING

from ...domain.devprops import decode_property
from ...domain.machine_errors import MissingKeyError, SourceError

if TYPE_CHECKING:
    from ...domain.devprops import DeviceProperty
    from ...domain.json_types import JsonValue

_CM_LOCATE_DEVNODE_PHANTOM = 0x1
_CR_SUCCESS = 0x00
_CR_NO_SUCH_DEVNODE = 0x0D
_CR_BUFFER_SMALL = 0x1A
_CR_NO_SUCH_VALUE = 0x25
_GUID_BYTES = 16


class _DevPropKey(ctypes.Structure):
    _fields_ = (("fmtid", ctypes.c_ubyte * _GUID_BYTES), ("pid", wintypes.ULONG))


def _key(prop: DeviceProperty) -> _DevPropKey:
    key = _DevPropKey()
    ctypes.memmove(key.fmtid, uuid.UUID(prop.key.fmtid).bytes_le, _GUID_BYTES)
    key.pid = prop.key.pid
    return key


def _refusal(code: int, what: str) -> SourceError:
    if code in {_CR_NO_SUCH_VALUE, _CR_NO_SUCH_DEVNODE}:
        return MissingKeyError(f"{what}: not set (CONFIGRET 0x{code:02X})")
    return SourceError(f"{what}: CONFIGRET 0x{code:02X}")


def _locate(cfgmgr: ctypes.CDLL, instance_id: str) -> wintypes.DWORD:
    node = wintypes.DWORD()
    code = int(cfgmgr.CM_Locate_DevNodeW(ctypes.byref(node), instance_id, _CM_LOCATE_DEVNODE_PHANTOM))
    if code != _CR_SUCCESS:
        raise _refusal(code, instance_id)
    return node


def _read(cfgmgr: ctypes.CDLL, *, node: wintypes.DWORD, prop: DeviceProperty, what: str) -> tuple[int, bytes]:
    key = _key(prop)
    kind = wintypes.ULONG()
    size = wintypes.ULONG(0)
    ask = cfgmgr.CM_Get_DevNode_PropertyW
    # First call sizes the buffer (CR_BUFFER_SMALL), the second fills it.
    code = int(ask(node, ctypes.byref(key), ctypes.byref(kind), None, ctypes.byref(size), 0))
    if code not in {_CR_SUCCESS, _CR_BUFFER_SMALL}:
        raise _refusal(code, what)
    buffer = ctypes.create_string_buffer(max(size.value, 1))
    code = int(ask(node, ctypes.byref(key), ctypes.byref(kind), buffer, ctypes.byref(size), 0))
    if code != _CR_SUCCESS:
        raise _refusal(code, what)
    return kind.value, buffer.raw[: size.value]


def device_property(instance_id: str, prop: DeviceProperty) -> JsonValue:
    """Return one property of a device instance, decoded by its property type.

    Raises:
        MissingKeyError: the device has no such property, or there is no such device.
        SourceError: not on Windows, or the configuration manager refused.
    """
    if sys.platform != "win32":
        raise SourceError(f"device properties need Windows, this is {sys.platform}")
    cfgmgr = ctypes.WinDLL("cfgmgr32")
    node = _locate(cfgmgr, instance_id)
    kind, raw = _read(cfgmgr, node=node, prop=prop, what=f"{instance_id} {prop.value}")
    return decode_property(kind, raw)


__all__ = ["device_property"]
