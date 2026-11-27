"""The ``devices`` section of a Linux reading: every device on the buses that tell machines apart.

For each bus below, every device is read one at a time: its modalias (the string the kernel
matches drivers against), its driver, and the id files that bus publishes. Then the loaded kernel
modules - the guest drivers a machine loads (``vmw_pvscsi``, ``vmxnet3``, ``hv_vmbus``,
``virtio_net``) are themselves a fingerprint - and the EDID of every display connector.

Input devices are a device class, not a bus (Linux has no ``/sys/bus/input``), so they are read
from ``/sys/class/input``; a bus this machine does not have is simply absent from the list.

Contents:
    * :class:`DeviceBus` - the buses read, and where each lists its devices.
    * :func:`read_devices` - read the section.

Every bus names the id files it publishes:

    >>> from fingerprint_machine.application.linux_devices import _ID_FILES
    >>> set(_ID_FILES) == set(DeviceBus)
    True
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from ..domain.edid import decode_edid
from ..domain.kernel_tables import parse_modules
from ..domain.machine_errors import MissingPathError
from .guard import guarded
from .linux_files import ATTRIBUTE_MAX_BYTES, optional_dir, text
from .linux_values import link_name, optional

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

#: An EDID is 128 bytes per block and at most 256 blocks; this is that bound.
_EDID_BYTES = 128 * 256
_DRM = "/sys/class/drm"


class DeviceBus(StrEnum):
    """A bus (or, for input, a class) whose devices a reading lists."""

    PCI = "pci"
    USB = "usb"
    VIRTIO = "virtio"
    VMBUS = "vmbus"
    SCSI = "scsi"
    INPUT = "input"
    PLATFORM = "platform"
    ACPI = "acpi"

    @property
    def directory(self) -> str:
        """Where the bus lists its devices."""
        if self is DeviceBus.INPUT:
            return "/sys/class/input"
        return f"/sys/bus/{self.value}/devices"


#: The id files each bus publishes per device; a device that lacks one simply has no such key.
_ID_FILES: Final[Mapping[DeviceBus, tuple[str, ...]]] = MappingProxyType(
    {
        DeviceBus.PCI: ("vendor", "device", "subsystem_vendor", "subsystem_device", "class", "revision"),
        DeviceBus.USB: ("idVendor", "idProduct", "bcdDevice", "bDeviceClass", "manufacturer", "product", "serial"),
        DeviceBus.VIRTIO: ("vendor", "device", "features"),
        DeviceBus.VMBUS: ("class_id", "device_id", "vendor", "device"),
        DeviceBus.SCSI: ("vendor", "model", "rev", "type", "scsi_level"),
        DeviceBus.INPUT: ("name", "phys", "uniq", "id/bustype", "id/vendor", "id/product", "id/version"),
        DeviceBus.PLATFORM: (),
        DeviceBus.ACPI: ("path", "hid", "uid", "adr", "status"),
    }
)


def _ids(system: LinuxSource, base: str, files: tuple[str, ...]) -> JsonObject:
    found = {name: optional(lambda name=name: text(system, f"{base}/{name}")) for name in files}
    return {name: value for name, value in found.items() if value is not None}


def _instance(system: LinuxSource, bus: DeviceBus, name: str) -> JsonObject:
    base = f"{bus.directory}/{name}"
    return {
        "instance_id": f"{bus.value}/{name}",
        "bus": bus.value,
        "name": name,
        "modalias": optional(lambda: text(system, f"{base}/modalias")),
        "driver": optional(lambda: link_name(system, f"{base}/driver")),
        "ids": _ids(system, base, _ID_FILES[bus]),
    }


def _names(system: LinuxSource, bus: DeviceBus) -> list[str]:
    """The devices on ``bus``: none when this machine does not have it."""
    names = optional_dir(system, bus.directory)
    return [n for n in names if n.startswith("input")] if bus is DeviceBus.INPUT else names


def _instances(system: LinuxSource) -> Iterator[JsonValue]:
    for bus in DeviceBus:
        for name in _names(system, bus):
            yield guarded(lambda bus=bus, name=name: _instance(system, bus, name))


def _modules(system: LinuxSource) -> JsonValue:
    return [m.as_json() for m in parse_modules(system.read_text("/proc/modules", max_bytes=ATTRIBUTE_MAX_BYTES))]


def _edid(system: LinuxSource, path: str) -> JsonValue:
    data = system.read_bytes(path, max_bytes=_EDID_BYTES)
    return decode_edid(data) if data else None


def _display(system: LinuxSource, connector: str) -> JsonObject | None:
    """One display connector with its EDID; None for a DRM entry that is not a connector."""
    base = f"{_DRM}/{connector}"
    try:
        if "edid" not in system.list_dir(base):
            return None
    except MissingPathError:  # a plain file such as ``version``
        return None
    return {
        "connector": connector,
        "status": optional(lambda: text(system, f"{base}/status")),
        "enabled": optional(lambda: text(system, f"{base}/enabled")),
        "edid": guarded(lambda: _edid(system, f"{base}/edid")),
    }


def _displays(system: LinuxSource) -> JsonValue:
    found = (guarded(lambda c=c: _display(system, c)) for c in system.list_dir(_DRM))
    return [d for d in found if d is not None]


def read_devices(src: LinuxSources) -> JsonValue:
    """Read the devices of every listed bus one at a time, the loaded modules and the displays."""
    system = src.system
    return {
        "instances": list(_instances(system)),
        "modules": guarded(lambda: _modules(system)),
        "displays": optional(lambda: _displays(system)),
    }


__all__ = ["DeviceBus", "read_devices"]
