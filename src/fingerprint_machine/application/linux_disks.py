"""The ``disks`` section of a Linux reading: block devices, their controllers, and what names them.

Every disk Linux sees (``/sys/block``) with its size, queue, scheduler, the identity its device
reports (vendor, model, serial, world wide name, the decoded VPD pages 0x80 and 0x83), the PCI
controller it hangs on and the chain of bridges above it, its partitions, and what udev recorded
for each (filesystem UUID and label, partition UUID). Then the storage controllers on their own:
NVMe controllers with their namespaces, SCSI hosts (``proc_name`` names the driver: ``vmw_pvscsi``,
``virtio_scsi``, ``hv_storvsc``, ``ahci``), Fibre Channel and SAS ports, and each controller's PCI
ids. A VMware PVSCSI controller also gets the ``sas_wwid`` its PCI serial number encodes.

Devices are read one at a time; every value is guarded, so one unreadable value is one recorded
error. A value only root may read (some VPD pages, the PCI serial number) is recorded as needing
root.

Contents:
    * :func:`read_linux_disks` - read the section.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, NamedTuple

from ..domain.blockdev import parse_scheduler, parse_udev_record, pci_addresses
from ..domain.identity import vmware_pvscsi_sas_wwid_from_dsn
from ..domain.vpd import decode_vpd_page80, decode_vpd_page83
from .guard import guarded
from .linux_files import optional_dir
from .linux_leaves import Leaf, flag, integer, pci_function, read_leaves, serial_number
from .linux_values import link_name, optional

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

_BLOCK = "/sys/block"
_UDEV_DATA = "/run/udev/data"
_DISK_LINKS = "/dev/disk"
_SECTOR_BYTES = 512
_VPD_BYTES = 64 * 1024
_PVSCSI = ("0x15ad", "0x07c0")
_NVME_NAMESPACE = re.compile(r"nvme\d+(?:c\d+)?n\d+")

_BLOCK_LEAVES = (
    Leaf("dev"), Leaf("removable", flag), Leaf("ro", flag), Leaf("hidden", flag), Leaf("serial"),
    Leaf("wwid"), Leaf("eui"), Leaf("nguid"), Leaf("uuid"), Leaf("nsid", integer),
)  # fmt: skip
_QUEUE_LEAVES = (
    Leaf("rotational", flag), Leaf("logical_block_size", integer), Leaf("physical_block_size", integer),
    Leaf("hw_sector_size", integer), Leaf("minimum_io_size", integer), Leaf("optimal_io_size", integer),
    Leaf("nr_requests", integer), Leaf("max_sectors_kb", integer), Leaf("max_hw_sectors_kb", integer),
    Leaf("discard_granularity", integer), Leaf("discard_max_hw_bytes", integer), Leaf("write_cache"),
    Leaf("zoned"), Leaf("dax", flag), Leaf("fua", flag), Leaf("add_random", flag),
)  # fmt: skip
_DEVICE_LEAVES = (
    Leaf("vendor"), Leaf("model"), Leaf("rev"), Leaf("serial"), Leaf("wwid"), Leaf("firmware_rev"),
    Leaf("queue_depth", integer), Leaf("scsi_level", integer), Leaf("type", integer), Leaf("state"),
    Leaf("cntlid", integer), Leaf("transport"), Leaf("subsysnqn"), Leaf("address"),
)  # fmt: skip
_PARTITION_LEAVES = (Leaf("partition", integer), Leaf("start", integer), Leaf("ro", flag), Leaf("dev"))
_NVME_LEAVES = (
    Leaf("serial"), Leaf("model"), Leaf("firmware_rev"), Leaf("cntlid", integer), Leaf("subsysnqn"),
    Leaf("transport"), Leaf("address"), Leaf("state"), Leaf("cntrltype"), Leaf("numa_node", integer),
    Leaf("queue_count", integer), Leaf("sqsize", integer),
)  # fmt: skip
_NAMESPACE_LEAVES = (Leaf("nsid", integer), Leaf("wwid"), Leaf("nguid"), Leaf("eui"), Leaf("uuid"))
_SCSI_HOST_LEAVES = (
    Leaf("proc_name"), Leaf("unique_id", integer), Leaf("host_wwn"), Leaf("can_queue", integer),
    Leaf("cmd_per_lun", integer), Leaf("sg_tablesize", integer), Leaf("nr_hw_queues", integer),
    Leaf("state"), Leaf("active_mode"), Leaf("supported_mode"), Leaf("prot_capabilities", integer),
)  # fmt: skip
_FC_HOST_LEAVES = (
    Leaf("port_name"), Leaf("node_name"), Leaf("permanent_port_name"), Leaf("port_id"), Leaf("port_type"),
    Leaf("port_state"), Leaf("speed"), Leaf("supported_speeds"), Leaf("fabric_name"), Leaf("symbolic_name"),
    Leaf("supported_classes"), Leaf("maxframe_size"),
)  # fmt: skip
_SAS_PHY_LEAVES = (
    Leaf("sas_address"), Leaf("phy_identifier", integer), Leaf("device_type"), Leaf("negotiated_linkrate"),
    Leaf("minimum_linkrate"), Leaf("maximum_linkrate"), Leaf("initiator_port_protocols"),
    Leaf("target_port_protocols"),
)  # fmt: skip
_SAS_DEVICE_LEAVES = (
    Leaf("sas_address"), Leaf("enclosure_identifier"), Leaf("bay_identifier", integer), Leaf("device_type"),
    Leaf("phy_identifier", integer), Leaf("initiator_port_protocols"), Leaf("target_port_protocols"),
)  # fmt: skip


def _place(src: LinuxSource, path: str) -> JsonObject:
    """Where a device sits: its sysfs device path and the PCI functions above it, controller last."""
    target = guarded(lambda: src.readlink(path))
    chain: list[JsonValue] = []
    chain.extend(pci_addresses(target) if isinstance(target, str) else [])
    return {"device_path": target, "pci_chain": chain, "controller": chain[-1] if chain else None}


def _udev(src: LinuxSource, udev_names: frozenset[str], dev: JsonValue) -> JsonValue:
    """What udev recorded for a ``major:minor``; None when udev has no record of it."""
    name = f"b{dev}"
    if not isinstance(dev, str) or name not in udev_names:
        return None
    return guarded(lambda: parse_udev_record(src.read_text(f"{_UDEV_DATA}/{name}")).as_json())


def _size(src: LinuxSource, directory: str) -> JsonValue:
    return guarded(lambda: int(src.read_text(f"{directory}/size").strip()) * _SECTOR_BYTES)


def _partition(src: LinuxSource, directory: str, udev_names: frozenset[str]) -> JsonObject:
    leaves = read_leaves(src, directory, _PARTITION_LEAVES)
    return {
        "name": directory.rsplit("/", 1)[-1],
        "size_bytes": _size(src, directory),
        **leaves,
        "udev": _udev(src, udev_names, leaves.get("dev")),
    }


def _partitions(src: LinuxSource, disk: str, names: Sequence[str], udev_names: frozenset[str]) -> list[JsonValue]:
    out: list[JsonValue] = []
    for name in names:
        directory = f"{_BLOCK}/{disk}/{name}"
        if name.startswith(disk) and name != disk and "partition" in optional_dir(src, directory):
            out.append(guarded(lambda directory=directory: _partition(src, directory, udev_names)))
    return out


def _vpd(src: LinuxSource, path: str, decode: Callable[[bytes], JsonValue]) -> JsonValue:
    return guarded(lambda: decode(src.read_bytes(path, max_bytes=_VPD_BYTES)))


def _designators(page: bytes) -> JsonValue:
    found: list[JsonValue] = [d.as_json() for d in decode_vpd_page83(page)]
    return found


def _device(src: LinuxSource, directory: str) -> JsonObject:
    """The identity the device behind a disk reports (SCSI INQUIRY, NVMe controller, virtio)."""
    names = set(src.list_dir(directory))
    out: JsonObject = {
        "name": guarded(lambda: link_name(src, directory)),
        "driver": optional(lambda: link_name(src, f"{directory}/driver")),
        **read_leaves(src, directory, _DEVICE_LEAVES),
    }
    if "vpd_pg80" in names:
        out["vpd_serial"] = _vpd(src, f"{directory}/vpd_pg80", decode_vpd_page80)
    if "vpd_pg83" in names:
        out["vpd_identifiers"] = _vpd(src, f"{directory}/vpd_pg83", _designators)
    return out


def _queue(src: LinuxSource, directory: str) -> JsonObject:
    """The request queue's limits, and its I/O scheduler where the queue has one (not zram, zvols)."""
    out = read_leaves(src, directory, _QUEUE_LEAVES)
    if "scheduler" in src.list_dir(directory):
        out["scheduler"] = guarded(lambda: parse_scheduler(src.read_text(f"{directory}/scheduler")).as_json())
    return out


def _block_device(src: LinuxSource, name: str, udev_names: frozenset[str]) -> JsonObject:
    directory = f"{_BLOCK}/{name}"
    names = src.list_dir(directory)
    leaves = read_leaves(src, directory, _BLOCK_LEAVES)
    return {
        "name": name,
        **_place(src, directory),
        "size_bytes": _size(src, directory),
        **leaves,
        "queue": guarded(lambda: _queue(src, f"{directory}/queue")) if "queue" in names else None,
        "device": guarded(lambda: _device(src, f"{directory}/device")) if "device" in names else None,
        "udev": _udev(src, udev_names, leaves.get("dev")),
        "partitions": _partitions(src, name, names, udev_names),
    }


def _namespaces(src: LinuxSource, directory: str) -> list[JsonValue]:
    out: list[JsonValue] = []
    for name in src.list_dir(directory):
        if _NVME_NAMESPACE.fullmatch(name):
            path = f"{directory}/{name}"
            out.append({"name": name, **read_leaves(src, path, _NAMESPACE_LEAVES)})
    return out


def _nvme_controller(src: LinuxSource, name: str) -> JsonObject:
    directory = f"/sys/class/nvme/{name}"
    return {
        "name": name,
        **_place(src, directory),
        **read_leaves(src, directory, _NVME_LEAVES),
        "namespaces": guarded(lambda: _namespaces(src, directory)),
    }


def _class_device(src: LinuxSource, directory: str, leaves: Sequence[Leaf]) -> JsonObject:
    return {"name": directory.rsplit("/", 1)[-1], **_place(src, directory), **read_leaves(src, directory, leaves)}


def _class_devices(src: LinuxSource, device_class: str, leaves: Sequence[Leaf]) -> list[JsonValue]:
    """Every device of a sysfs class (none when the class does not exist), its place and leaves."""
    base = f"/sys/class/{device_class}"
    return [guarded(lambda name=name: _class_device(src, f"{base}/{name}", leaves)) for name in optional_dir(src, base)]


def _pvscsi_wwid(src: LinuxSource, address: str) -> JsonValue:
    dsn = serial_number(src, address)
    if dsn is None:
        return None
    vendor, device = (int(i, 16) for i in _PVSCSI)
    return vmware_pvscsi_sas_wwid_from_dsn(vendor=vendor, device=device, dsn=dsn)


def _controller(src: LinuxSource, address: str) -> JsonObject:
    """A storage controller's PCI ids; a PVSCSI controller also its sasWWID (None without a DSN)."""
    ids = pci_function(src, address)
    if (ids.get("vendor"), ids.get("device")) == _PVSCSI:
        ids["sas_wwid"] = guarded(lambda: _pvscsi_wwid(src, address))
    return ids


def _controllers(records: Sequence[JsonValue]) -> list[str]:
    """The distinct PCI controllers the records hang on, in first-seen order."""
    seen: dict[str, None] = {}
    for record in records:
        controller = record.get("controller") if isinstance(record, dict) else None
        if isinstance(controller, str):
            seen.setdefault(controller, None)
    return list(seen)


def _disk_links(src: LinuxSource) -> JsonObject:
    """``/dev/disk/by-*``: each link name and the device it points at, per kind."""
    out: JsonObject = {}
    for kind in src.list_dir(_DISK_LINKS):
        directory = f"{_DISK_LINKS}/{kind}"
        out[kind] = guarded(
            lambda directory=directory: {
                name: guarded(lambda name=name: link_name(src, f"{directory}/{name}"))
                for name in src.list_dir(directory)
            }
        )
    return out


class _UdevDatabase(NamedTuple):
    """The udev database's entry names, and what the reading records about the database."""

    names: frozenset[str]
    record: JsonValue


def _udev_names(src: LinuxSource) -> _UdevDatabase:
    """The udev database's entry names, and what the reading records about the database."""
    names = guarded(lambda: list(src.list_dir(_UDEV_DATA)))
    if isinstance(names, list):
        return _UdevDatabase(names=frozenset(str(n) for n in names), record={"entries": len(names)})
    return _UdevDatabase(names=frozenset(), record=names)


def read_linux_disks(src: LinuxSources) -> JsonValue:
    """Read every block device, storage controller and storage port of the machine."""
    system = src.system
    udev = _udev_names(system)
    disks: list[JsonValue] = [
        guarded(lambda name=name: _block_device(system, name, udev.names)) for name in system.list_dir(_BLOCK)
    ]
    nvme: list[JsonValue] = [
        guarded(lambda name=name: _nvme_controller(system, name)) for name in optional_dir(system, "/sys/class/nvme")
    ]
    hosts = _class_devices(system, "scsi_host", _SCSI_HOST_LEAVES)
    controllers: list[JsonValue] = [
        guarded(lambda address=address: _controller(system, address))
        for address in _controllers([*disks, *nvme, *hosts])
    ]
    return {
        "block_devices": disks,
        "nvme_controllers": nvme,
        "scsi_hosts": hosts,
        "fc_hosts": _class_devices(system, "fc_host", _FC_HOST_LEAVES),
        "sas_phys": _class_devices(system, "sas_phy", _SAS_PHY_LEAVES),
        "sas_devices": _class_devices(system, "sas_device", _SAS_DEVICE_LEAVES),
        "controllers": controllers,
        "disk_links": guarded(lambda: _disk_links(system)),
        "udev_database": udev.record,
    }


__all__ = ["read_linux_disks"]
