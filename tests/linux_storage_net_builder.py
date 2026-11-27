"""Synthetic Linux machines for the disks and network sections: a VMware-like and a KVM-like guest.

Each machine is a tree of sysfs, procfs, ``/run`` and ``/dev`` files plus the answers that are not
files (symbolic links, ethtool, netlink), in the shape :class:`FixtureLinuxSource` reads. Every
serial, address and name is invented; ids follow the real devices (PVSCSI ``15ad:07c0``, vmxnet3
``15ad:07b0``, virtio ``1af4:*``, QEMU NVMe ``1b36:0010``) so the readers see realistic shapes.

Contents:
    * :class:`Flavour` - which guest to build.
    * :data:`PVSCSI_DSN`, :data:`PVSCSI_WWID` - the PVSCSI serial and the sasWWID it encodes.
    * :func:`write_storage_net_tree` - write the files of one guest under a root directory.
    * :func:`storage_net_answers` - the non-file answers of that guest.
"""

from __future__ import annotations

import struct
from enum import StrEnum
from typing import TYPE_CHECKING

from machine_builder import cpuid_document
from netlink_messages import address, done, link, neighbour, route

from fingerprint_machine.domain.ethtool import (
    RINGS,
    StringSet,
    driver_info_request,
    features_request,
    link_settings_request,
    permanent_address_request,
    string_count_request,
    strings_request,
)

if TYPE_CHECKING:
    from pathlib import Path

    from fingerprint_machine.domain.json_types import JsonObject, JsonValue


class Flavour(StrEnum):
    """The synthetic guests."""

    VMWARE = "vmware"
    KVM = "kvm"


#: The PVSCSI controller's PCI serial number and the sasWWID VMware built it from (halves swapped).
PVSCSI_DSN = 0x0123ABCD50050560
PVSCSI_WWID = "500505600123abcd"
_VMXNET3_DSN = 0x000C29FFFF000001
FS_UUID = "0000aaaa-1111-2222-3333-444455556666"
_PCI = "../../../bus/pci/drivers"


def _config(dsn: int | None, *, size: int = 4096) -> bytes:
    """The first ``size`` bytes of a PCI Express function's space; a DSN at 0x100 when given.

    The capability list starts at 0x40 (a PCI Express capability), so a 64-byte read, which is
    what an unprivileged reader gets, stops before it.
    """
    space = bytearray(max(size, 0x44))
    struct.pack_into("<H", space, 0x06, 0x0010)  # status: capability list present
    space[0x34] = 0x40
    space[0x40:0x42] = bytes([0x10, 0x00])  # PCI Express capability, the last in the list
    if dsn is not None:
        struct.pack_into("<III", space, 0x100, 0x0003 | 1 << 16, dsn & 0xFFFFFFFF, dsn >> 32)
    return bytes(space[:size])


def _vpd80(serial: str) -> bytes:
    body = serial.encode().ljust(20)
    return bytes([0, 0x80, 0, len(body)]) + body


def _vpd83(naa: str) -> bytes:
    designator = bytes([0x01, 0x03, 0, len(bytes.fromhex(naa))]) + bytes.fromhex(naa)
    return bytes([0, 0x83, 0, len(designator)]) + designator


def _pci(address_: str, *, vendor: str, device: str, pci_class: str, config: bytes) -> dict[str, bytes]:
    base = f"sys/bus/pci/devices/{address_}"
    leaves = {"vendor": vendor, "device": device, "subsystem_vendor": vendor, "subsystem_device": device}
    leaves |= {"class": pci_class, "revision": "0x01"}
    files = {f"{base}/{name}": f"{value}\n".encode() for name, value in leaves.items()}
    files[f"{base}/config"] = config
    return files


def _leaves(base: str, values: dict[str, str]) -> dict[str, bytes]:
    return {f"{base}/{name}": f"{value}\n".encode() for name, value in values.items()}


def _interface(name: str, values: dict[str, str], *, queues: int) -> dict[str, bytes]:
    files = _leaves(f"sys/class/net/{name}", values)
    for kind, leaf in (("rx", "rps_cpus"), ("tx", "xps_cpus")):
        for number in range(queues):
            files[f"sys/class/net/{name}/queues/{kind}-{number}/{leaf}"] = b"0\n"
    return files


_LOOPBACK = {"ifindex": "1", "address": "00:00:00:00:00:00", "mtu": "65536", "type": "772", "flags": "0x9"}


def _vmware_files() -> dict[str, bytes]:
    files = _leaves("sys/block/sda", {"size": "41943040", "dev": "8:0", "removable": "0", "ro": "0"})
    files |= _leaves(
        "sys/block/sda/queue",
        {"rotational": "1", "logical_block_size": "512", "physical_block_size": "512", "nr_requests": "254",
         "scheduler": "[mq-deadline] none"},
    )  # fmt: skip
    files |= _leaves(
        "sys/block/sda/device",
        {"vendor": "VMware  ", "model": "Virtual disk    ", "rev": "2.0 ", "queue_depth": "254", "state": "running",
         "wwid": "naa.6000c29aaaaaaaaaaaaaaaaaaaaaaa"},
    )  # fmt: skip
    files["sys/block/sda/device/vpd_pg80"] = _vpd80("VMW-DISK-0001")
    files["sys/block/sda/device/vpd_pg83"] = _vpd83("6000c29aaaaaaaaaaaaaaaaaaaaaaaaa")
    files |= _leaves("sys/block/sda/sda1", {"partition": "1", "start": "2048", "size": "1048576", "dev": "8:1"})
    files["run/udev/data/b8:1"] = (
        f"S:disk/by-uuid/{FS_UUID}\nE:ID_FS_UUID={FS_UUID}\nE:ID_FS_TYPE=ext4\nE:ID_PART_ENTRY_UUID=0000bbbb-01\n"
    ).encode()
    files[f"dev/disk/by-uuid/{FS_UUID}"] = b""
    files |= _leaves("sys/class/scsi_host/host2", {"proc_name": "vmw_pvscsi", "unique_id": "2", "can_queue": "254"})
    files |= _pci("0000:03:00.0", vendor="0x15ad", device="0x07c0", pci_class="0x010700", config=_config(PVSCSI_DSN))
    files |= _pci("0000:0b:00.0", vendor="0x15ad", device="0x07b0", pci_class="0x020000", config=_config(_VMXNET3_DSN))
    files |= _interface(
        "ens192",
        {"ifindex": "2", "address": "00:50:56:00:00:01", "mtu": "1500", "type": "1", "flags": "0x1003",
         "carrier": "1", "speed": "10000", "duplex": "full", "operstate": "up"},
        queues=2,
    )  # fmt: skip
    files |= _interface("lo", _LOOPBACK, queues=1)
    files["sys/class/net/bonding_masters"] = b"\n"
    files["etc/resolv.conf"] = b"nameserver 192.0.2.53\nsearch example.test\n"
    return files


_VMWARE_LINKS = {
    "/sys/block/sda": "../devices/pci0000:00/0000:00:15.0/0000:03:00.0/host2/target2:0:0/2:0:0:0/block/sda",
    "/sys/block/sda/device": "../../../2:0:0:0",
    "/sys/block/sda/device/driver": "../../../../../../../bus/scsi/drivers/sd",
    "/sys/class/scsi_host/host2": "../../devices/pci0000:00/0000:00:15.0/0000:03:00.0/host2/scsi_host/host2",
    "/sys/bus/pci/devices/0000:03:00.0/driver": f"{_PCI}/vmw_pvscsi",
    "/sys/bus/pci/devices/0000:0b:00.0/driver": f"{_PCI}/vmxnet3",
    f"/dev/disk/by-uuid/{FS_UUID}": "../../sda1",
    "/sys/class/net/ens192": "../../devices/pci0000:00/0000:00:16.0/0000:0b:00.0/net/ens192",
    "/sys/class/net/lo": "../../devices/virtual/net/lo",
}


def _kvm_files() -> dict[str, bytes]:
    files = _leaves("sys/block/vda", {"size": "20971520", "dev": "252:0", "serial": "KVM-DISK-0001", "ro": "0"})
    files |= _leaves("sys/block/vda/queue", {"rotational": "1", "scheduler": "[none] mq-deadline"})
    files["sys/block/vda/device/features"] = b"0\n"
    files |= _leaves("sys/block/nvme0n1", {"size": "2097152", "dev": "259:0", "wwid": "eui.0000000000000001"})
    nvme = {"serial": "NVME-SER-0001       ", "model": "QEMU NVMe Ctrl", "firmware_rev": "9.0", "cntlid": "0",
            "subsysnqn": "nqn.2019-08.org.qemu:NVME-SER-0001", "transport": "pcie", "address": "0000:00:06.0",
            "state": "live"}  # fmt: skip
    files |= _leaves("sys/block/nvme0n1/device", nvme)
    files |= _leaves("sys/class/nvme/nvme0", nvme)
    files |= _leaves("sys/class/nvme/nvme0/nvme0n1", {"nsid": "1", "wwid": "eui.0000000000000001"})
    files |= _leaves("sys/class/scsi_host/host0", {"proc_name": "virtio_scsi", "unique_id": "0"})
    # An unprivileged read of a function's config gets 64 bytes; a conventional function has 256.
    files |= _pci("0000:00:05.0", vendor="0x1af4", device="0x1001", pci_class="0x010000", config=_config(None, size=64))
    files |= _pci(
        "0000:00:06.0", vendor="0x1b36", device="0x0010", pci_class="0x010802", config=_config(None, size=256)
    )
    files |= _pci("0000:00:03.0", vendor="0x1af4", device="0x1041", pci_class="0x020000", config=_config(None, size=64))
    files |= _pci("0000:00:07.0", vendor="0x1af4", device="0x1004", pci_class="0x010000", config=_config(None, size=64))
    files |= _interface(
        "eth0",
        {"ifindex": "2", "address": "52:54:00:00:00:01", "mtu": "1500", "type": "1", "flags": "0x1003"},
        queues=1,
    )
    files |= _interface("lo", _LOOPBACK, queues=1)
    files["etc/resolv.conf"] = b"nameserver 127.0.0.53\n"
    files["run/systemd/resolve/resolv.conf"] = b"nameserver 192.0.2.53\n"
    return files


_KVM_LINKS = {
    "/sys/block/vda": "../devices/pci0000:00/0000:00:05.0/virtio2/block/vda",
    "/sys/block/vda/device": "../../../virtio2",
    "/sys/block/vda/device/driver": "../../../../bus/virtio/drivers/virtio_blk",
    "/sys/block/nvme0n1": "../devices/pci0000:00/0000:00:06.0/nvme/nvme0/nvme0n1",
    "/sys/block/nvme0n1/device": "../../nvme0",
    "/sys/class/nvme/nvme0": "../../devices/pci0000:00/0000:00:06.0/nvme/nvme0",
    "/sys/class/scsi_host/host0": "../../devices/pci0000:00/0000:00:07.0/virtio3/host0/scsi_host/host0",
    "/sys/bus/pci/devices/0000:00:05.0/driver": f"{_PCI}/virtio-pci",
    "/sys/bus/pci/devices/0000:00:06.0/driver": f"{_PCI}/nvme",
    "/sys/bus/pci/devices/0000:00:03.0/driver": f"{_PCI}/virtio-pci",
    "/sys/bus/pci/devices/0000:00:07.0/driver": f"{_PCI}/virtio-pci",
    "/sys/class/net/eth0": "../../devices/pci0000:00/0000:00:03.0/virtio0/net/eth0",
    "/sys/class/net/lo": "../../devices/virtual/net/lo",
}


def write_storage_net_tree(root: Path, flavour: Flavour) -> Path:
    """Write the files of one synthetic guest under ``root`` and return ``root``."""
    files = _vmware_files() if flavour is Flavour.VMWARE else _kvm_files()
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)  # bytes: Windows would write a newline as CRLF
    return root


def _text(value: str, size: int) -> bytes:
    return value.encode().ljust(size, b"\0")


def _drvinfo(driver: str, bus: str) -> bytes:
    return struct.pack(
        "<I32s32s32s32s32s12sIIIII",
        0x03, _text(driver, 32), _text("1.0", 32), _text("", 32), _text(bus, 32), _text("", 32), bytes(12),
        0, 0, 0, 0, 0,
    )  # fmt: skip


def _nic_answers(*, driver: str, bus: str, mac: str) -> JsonObject:
    """The ethtool answers of one NIC, keyed by request bytes as the fixture reads them."""
    names = ["rx-checksum", "tx-tcp-segmentation"]
    link_probe = bytearray(link_settings_request(0))
    struct.pack_into("<b", link_probe, 15, -1)
    settings = bytearray(link_settings_request(1))
    struct.pack_into("<IB", settings, 4, 10000, 1)
    struct.pack_into("<I", settings, 48, 1 << 12)  # supported: mode 12
    answers: dict[bytes, bytes] = {
        driver_info_request(): _drvinfo(driver, bus),
        permanent_address_request(): struct.pack("<II", 0x20, 6) + bytes.fromhex(mac.replace(":", "")) + bytes(26),
        string_count_request(StringSet.FEATURES): struct.pack("<IIQI", 0x37, 0, 1 << 4, len(names)),
        strings_request(StringSet.FEATURES, len(names)): struct.pack("<III", 0x1B, 4, len(names))
        + b"".join(_text(n, 32) for n in names),
        features_request(len(names)): struct.pack("<II", 0x3A, 1) + struct.pack("<IIII", 0b10, 0b11, 0b11, 0),
        link_settings_request(0): bytes(link_probe),
        link_settings_request(1): bytes(settings),
        RINGS.request(): struct.pack("<9I", 0x10, 4096, 0, 0, 4096, 1024, 0, 0, 512),
    }
    return {request.hex(): answer.hex() for request, answer in answers.items()}


def _netlink(flavour: Flavour) -> JsonObject:
    if flavour is Flavour.VMWARE:
        nic, mac, ip = "ens192", "00:50:56:00:00:01", "192.0.2.10"
    else:
        nic, mac, ip = "eth0", "52:54:00:00:00:01", "198.51.100.10"
    links = [link(index=1, name="lo", mac="00:00:00:00:00:00", mtu=65536), link(index=2, name=nic, mac=mac), done()]
    addresses = [address(index=1, ip="127.0.0.1", prefix=8, label="lo"), address(index=2, ip=ip, prefix=24, label=nic)]
    routes = [
        route(destination=None, gateway="192.0.2.1", out_index=2),
        route(destination="203.0.113.0", gateway=None, out_index=9, prefix=24),  # names no interface
    ]
    neighbours = [neighbour(index=2, ip="192.0.2.1", mac="02:00:00:00:00:fe")]
    tables: dict[str, list[bytes]] = {"links": links[:-1], "addresses": addresses, "routes": routes}
    tables["neighbours"] = neighbours
    out: JsonObject = {}
    for name, messages in tables.items():
        hexed: list[JsonValue] = [m.hex() for m in messages]
        out[name] = hexed
    return out


def storage_net_answers(flavour: Flavour) -> JsonObject:
    """Return the non-file answers of one synthetic guest: links, ethtool, netlink and CPUID."""
    if flavour is Flavour.VMWARE:
        links: JsonObject = dict(_VMWARE_LINKS)
        ethtool: JsonObject = {"ens192": _nic_answers(driver="vmxnet3", bus="0000:0b:00.0", mac="00:50:56:00:00:01")}
        hypervisor = b"VMwareVMware"
    else:
        links = dict(_KVM_LINKS)
        ethtool = {"eth0": _nic_answers(driver="virtio_net", bus="0000:00:03.0", mac="52:54:00:00:00:01")}
        hypervisor = b"KVMKVMKVM"
    return {
        "cpuid": cpuid_document(hypervisor=hypervisor),
        "links": links,
        "ethtool": ethtool,
        "netlink": _netlink(flavour),
    }


__all__ = ["FS_UUID", "PVSCSI_DSN", "PVSCSI_WWID", "Flavour", "storage_net_answers", "write_storage_net_tree"]
