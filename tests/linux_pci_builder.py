"""Build the PCI and device files of a synthetic Linux machine: a VMware-like and a KVM-like guest.

Each machine is written under a tree root that mirrors ``/``, next to what
:func:`linux_builder.write_linux_tree` writes. The PCI devices sit in ``/sys/devices`` behind a
root port, ``/sys/bus/pci/devices`` links to them, and the interrupt files (``/proc/interrupts``,
``/proc/irq``, ``/sys/kernel/irq``) and the device buses (virtio, scsi, usb, acpi, input, drm)
are filled to match. Unprivileged, the configuration space is 64 bytes and the I/O maps print
every address as zero, as the kernel shows them to a user that is not root.

The tree uses symbolic links and file names with colons, as sysfs does, so it can be written on a
POSIX filesystem only. Every value is invented.

Contents:
    * :class:`Flavour` - which guest to write.
    * :func:`write_pci_tree` - write it.
    * :data:`PVSCSI_ADDRESS`, :data:`VIRTIO_NET_ADDRESS` - the endpoint of each guest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from edid_bytes import edid_block
from pci_bytes import CAP_EXP, CAP_MSIX, Config, endpoint_config, root_port_config

if TYPE_CHECKING:
    from pathlib import Path

#: The VMware-like guest's PVSCSI controller and its root port.
PVSCSI_ADDRESS = "0000:03:00.0"
VMWARE_ROOT_PORT = "0000:00:15.0"
#: The KVM-like guest's virtio network device and its root port.
VIRTIO_NET_ADDRESS = "0000:01:00.0"
KVM_ROOT_PORT = "0000:00:02.0"


class Flavour(StrEnum):
    """Which synthetic guest to write."""

    VMWARE = "vmware"
    KVM = "kvm"


@dataclass(frozen=True)
class _Device:
    """One PCI function: where it sits and what its sysfs files say."""

    chain: tuple[str, ...]
    config: Config
    class_code: str
    driver: str | None = None
    irq: int = 0
    msi: dict[int, str] = field(default_factory=dict[int, str])
    link: tuple[str, str] | None = None
    resource: str = ""
    acpi_path: str | None = None

    @property
    def address(self) -> str:
        return self.chain[-1]


def _write(root: Path, relative: str, content: bytes | str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    # Bytes, not write_text: write_text would translate newlines on some platforms.
    target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)


def _link(root: Path, relative: str, target: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)


def _ids(config: Config) -> dict[str, str]:
    data = config.bytes(64)

    def word(offset: int) -> str:
        return f"0x{int.from_bytes(data[offset : offset + 2], 'little'):04x}"

    return {
        "vendor": word(0x00),
        "device": word(0x02),
        "subsystem_vendor": word(0x2C),
        "subsystem_device": word(0x2E),
        "revision": f"0x{data[0x08]:02x}",
    }


def _write_device(root: Path, device: _Device, *, privileged: bool) -> None:
    sysfs = "sys/devices/pci0000:00/" + "/".join(device.chain)
    files = {**_ids(device.config), "class": device.class_code, "irq": str(device.irq), "numa_node": "-1"}
    for name, value in files.items():
        _write(root, f"{sysfs}/{name}", value + "\n")
    _write(root, f"{sysfs}/resource", device.resource)
    _write(root, f"{sysfs}/config", device.config.bytes(None if privileged else 64))
    for irq, mode in device.msi.items():
        _write(root, f"{sysfs}/msi_irqs/{irq}", mode + "\n")
    if device.link is not None:
        speed, width = device.link
        for prefix in ("current", "max"):
            _write(root, f"{sysfs}/{prefix}_link_speed", speed + "\n")
            _write(root, f"{sysfs}/{prefix}_link_width", width + "\n")
    if device.driver is not None:
        _link(root, f"{sysfs}/driver", f"../../../../bus/pci/drivers/{device.driver}")
    if device.acpi_path is not None:
        node = f"sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:{len(device.chain):02x}"
        _write(root, f"{node}/path", device.acpi_path + "\n")
        _link(root, f"{sysfs}/firmware_node", "/".join([".."] * (len(device.chain) + 2)) + "/" + node[len("sys/") :])
    _link(root, f"sys/bus/pci/devices/{device.address}", "../../../" + sysfs[len("sys/") :])


def _vmware_devices() -> list[_Device]:
    host = Config(256).put(0x00, "HH", 0x8086, 0x7190).put(0x08, "I", 0x06000001)
    port = root_port_config().put(0x00, "HH", 0x15AD, 0x07A0)
    return [
        _Device(("0000:00:00.0",), host, "0x060000"),
        _Device((VMWARE_ROOT_PORT,), port, "0x060400", driver="pcieport", irq=24, msi={24: "msi"}),
        _Device(
            (VMWARE_ROOT_PORT, PVSCSI_ADDRESS),
            endpoint_config(),
            "0x010700",
            driver="vmw_pvscsi",
            irq=56,
            msi={56: "msix", 57: "msix"},
            link=("5.0 GT/s PCIe", "32"),
            resource="0x0000000000004000 0x0000000000004007 0x0000000000040101\n"
            "0x00000000fd5f8000 0x00000000fd5fffff 0x0000000000040200\n"
            "0x0000000000000000 0x0000000000000000 0x0000000000000000\n",
            acpi_path=r"\_SB_.PCI0.PE40.S1F0",
        ),
    ]


def _virtio_config() -> Config:
    cfg = Config(4096).put(0x00, "HH", 0x1AF4, 0x1041).put(0x04, "HH", 0x0507, 0x0010)
    cfg.put(0x08, "I", 0x02000001).put(0x2C, "HH", 0x1AF4, 0x1100).put(0x34, "B", 0x40).put(0x3C, "BB", 0xFF, 1)
    cfg.cap(0x40, 0x09, 0x50).cap(0x50, CAP_MSIX, 0x60).put(0x52, "H", 0x8000 | 2).put(0x54, "II", 1, 0x801)
    cfg.cap(0x60, CAP_EXP, 0x00).put(0x62, "H", 0x0002)
    return cfg


def _kvm_devices() -> list[_Device]:
    host = Config(256).put(0x00, "HH", 0x8086, 0x29C0).put(0x08, "I", 0x06000002)
    port = root_port_config().put(0x00, "HH", 0x1B36, 0x000C)
    return [
        _Device(("0000:00:00.0",), host, "0x060000"),
        _Device((KVM_ROOT_PORT,), port, "0x060400", driver="pcieport", irq=24, msi={24: "msi"}),
        _Device(
            (KVM_ROOT_PORT, VIRTIO_NET_ADDRESS),
            _virtio_config(),
            "0x020000",
            driver="virtio-pci",
            irq=22,
            msi={25: "msix", 26: "msix", 27: "msix"},
            link=("2.5 GT/s PCIe", "1"),
            resource="0x00000000fe800000 0x00000000fe803fff 0x000000000014220c\n",
        ),
    ]


def _interrupts(devices: list[_Device]) -> str:
    lines = ["           CPU0       CPU1", "  0:         21          0   IO-APIC   2-edge      timer"]
    for device in devices:
        for irq, mode in device.msi.items():
            chip = f"PCI-{'MSIX' if mode == 'msix' else 'MSI'}-{device.address}"
            lines.append(f"{irq:3d}:          5        700   {chip}    0-edge      {device.driver}")
    lines += ["NMI:          3          4   Non-maskable interrupts", "ERR:          0", ""]
    return "\n".join(lines)


def _write_irqs(root: Path, devices: list[_Device]) -> None:
    _write(root, "proc/interrupts", _interrupts(devices))
    irqs = {0: ("IO-APIC", "2", "edge", "timer")}
    for device in devices:
        irqs |= dict.fromkeys(device.msi, ("PCI-MSI", "0", "edge", device.driver or ""))
    for irq, (chip, hwirq, kind, action) in irqs.items():
        values = {"chip_name": chip, "hwirq": hwirq, "type": kind, "name": "", "actions": action, "wakeup": "disabled"}
        for name, value in values.items():
            _write(root, f"sys/kernel/irq/{irq}/{name}", value + "\n")
        _write(root, f"proc/irq/{irq}/smp_affinity_list", "0-1\n")
        _write(root, f"proc/irq/{irq}/effective_affinity_list", "1\n")
        _write(root, f"proc/irq/{irq}/node", "0\n")


def _write_maps(root: Path, *, privileged: bool) -> None:
    def span(start: str, end: str) -> str:
        return f"{start}-{end}" if privileged else f"{'0' * len(start)}-{'0' * len(end)}"

    _write(root, "proc/ioports", f"{span('0000', '0cf7')} : PCI Bus 0000:00\n  {span('0000', '001f')} : dma1\n")
    _write(
        root, "proc/iomem", f"{span('00000000', '00000fff')} : Reserved\n{span('00100000', 'bfffffff')} : System RAM\n"
    )
    _write(root, "proc/dma", " 4: cascade\n")


def _write_vmware_buses(root: Path) -> None:
    _write(root, "sys/bus/scsi/devices/2:0:0:0/vendor", "VMware  \n")
    _write(root, "sys/bus/scsi/devices/2:0:0:0/model", "Virtual disk    \n")
    _write(root, "sys/bus/scsi/devices/2:0:0:0/modalias", "scsi:t-0x00\n")
    _link(root, "sys/bus/scsi/devices/2:0:0:0/driver", "../../../../bus/scsi/drivers/sd")
    _write(root, "sys/class/input/input2/name", "VMware VMware Virtual USB Mouse\n")
    _write(root, "sys/class/input/input2/id/vendor", "0e0f\n")
    _write(root, "sys/class/input/mice/dev", "13:63\n")
    _write(root, "sys/class/drm/card0-Virtual-1/status", "connected\n")
    _write(root, "sys/class/drm/card0-Virtual-1/edid", edid_block(vendor="VMW", texts={0xFC: "VMware SVGA"}))
    _write(root, "proc/modules", "vmw_pvscsi 28672 2 - Live 0x0000000000000000\nvmxnet3 69632 0 - Live 0x0\n")


def _write_kvm_buses(root: Path) -> None:
    virtio = "sys/devices/pci0000:00/0000:00:02.0/0000:01:00.0/virtio0"
    _write(root, f"{virtio}/vendor", "0x1af4\n")
    _write(root, f"{virtio}/device", "0x0001\n")
    _write(root, f"{virtio}/modalias", "virtio:d00000001v00001AF4\n")
    _link(root, f"{virtio}/driver", "../../../../../bus/virtio/drivers/virtio_net")
    _link(root, "sys/bus/virtio/devices/virtio0", "../../../devices/pci0000:00/0000:00:02.0/0000:01:00.0/virtio0")
    _write(root, "sys/bus/acpi/devices/PNP0A08:00/hid", "PNP0A08\n")
    _write(root, "sys/bus/acpi/devices/PNP0A08:00/path", r"\_SB_.PCI0" + "\n")
    _write(root, "sys/class/drm/card0-Virtual-1/status", "connected\n")
    _write(root, "sys/class/drm/card0-Virtual-1/edid", b"")
    _write(root, "sys/class/drm/version", "drm 1.1.0 20060810\n")
    _write(root, "proc/modules", "virtio_net 69632 0 - Live 0x0\nnet_failover 24576 1 virtio_net, Live 0x0\n")


def write_pci_tree(root: Path, flavour: Flavour, *, privileged: bool = True) -> Path:
    """Write the PCI devices, interrupts, maps and device buses of one guest under ``root``."""
    devices = _vmware_devices() if flavour is Flavour.VMWARE else _kvm_devices()
    for device in devices:
        _write_device(root, device, privileged=privileged)
    _write_irqs(root, devices)
    _write_maps(root, privileged=privileged)
    _write(root, "sys/class/drm/card0/dev", "226:0\n")
    if flavour is Flavour.VMWARE:
        _write(root, "sys/bus/pci/slots/160/address", "0000:03:00\n")
        _write_vmware_buses(root)
    else:
        _write(root, "sys/bus/pci/slots/0/address", "0000:01:00\n")
        _write_kvm_buses(root)
    return root


__all__ = [
    "KVM_ROOT_PORT",
    "PVSCSI_ADDRESS",
    "VIRTIO_NET_ADDRESS",
    "VMWARE_ROOT_PORT",
    "Flavour",
    "write_pci_tree",
]
