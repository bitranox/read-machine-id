"""Two synthetic Linux guests for the system sections: a VMware-like one and a KVM-like one.

Each is a directory tree that mirrors ``/`` (firmware tables, ``/proc``, ``/sys``, ``/etc``, unit
files, a LUKS header on a disk) plus the answers that are not files (CPUID, the TPM's NV indices).
The VMware-like guest boots UEFI with Secure Boot, a TPM with an EK certificate, an MSDM table
with a planted product key, AppArmor, and open-vm-tools running; the KVM-like guest boots BIOS
with no TPM, SELinux, and qemu-guest-agent and cloud-init running. Every value is invented.

No symbolic links are written: the trees are built on Windows runners too.

Contents:
    * :class:`Guest` - which guest.
    * :func:`write_system_tree` - write a guest's files under a root.
    * :func:`system_answers` - its non-file answers.
    * :data:`LUKS_UUID`, :data:`MACHINE_ID`, :data:`EK_INDEX` - values the tests look for.
"""

from __future__ import annotations

import json
import struct
from enum import StrEnum
from typing import TYPE_CHECKING

from linux_builder import linux_answers
from machine_builder import PLANTED_KEY, acpi_table, ek_certificate_der, smbios_table

if TYPE_CHECKING:
    from pathlib import Path

    from fingerprint_machine.domain.json_types import JsonObject

LUKS_UUID = "0a1b2c3d-0000-4000-8000-00000000c0de"
MACHINE_ID = "0123456789abcdef0123456789abcdef"
EK_INDEX = "0x01c00002"
_EFI_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
_SHIM = "605dab50-e046-4300-abb6-3dd810dd8b23"


class Guest(StrEnum):
    """The two synthetic guests."""

    VMWARE = "vmware"
    KVM = "kvm"


def _sm3_entry_point() -> bytes:
    return b"_SM3_" + bytes([0, 0x18, 3, 1, 0, 1, 0]) + struct.pack("<IQ", len(smbios_table()), 0x000E0000)


def _luks2_header() -> bytes:
    area = {
        "keyslots": {"0": {"type": "luks2", "area": {"key_size": 64}}},
        "tokens": {},
        "segments": {"0": {"type": "crypt", "offset": "16777216", "size": "dynamic", "encryption": "aes-xts-plain64"}},
        "digests": {"0": {"type": "pbkdf2", "digest": "SYNTHETICDIGEST"}},
        "config": {"json_size": "12288"},
    }
    header = bytearray(4096)
    header[0:8] = b"LUKS\xba\xbe" + struct.pack(">H", 2)
    header[8:16] = struct.pack(">Q", 16384)
    header[72:78] = b"sha256"
    header[168 : 168 + len(LUKS_UUID)] = LUKS_UUID.encode()
    return bytes(header) + json.dumps(area).encode().ljust(16384 - 4096, b"\0")


def _efivar(value: int) -> bytes:
    return struct.pack("<I", 0x06) + bytes([value])


def _common_files(guest: Guest) -> dict[str, str | bytes]:
    luks_hex = LUKS_UUID.replace("-", "")
    return {
        "sys/firmware/dmi/tables/DMI": smbios_table(),
        "sys/firmware/dmi/tables/smbios_entry_point": _sm3_entry_point(),
        "sys/class/dmi/id/bios_vendor": "Example BIOS Co\n",
        "sys/class/dmi/id/product_serial": "SER-0001\n",
        "sys/class/dmi/id/product_uuid": "04030201-0605-0807-090a-0b0c0d0e0f10\n",
        "sys/class/dmi/id/modalias": f"dmi:bvnExample:svn{guest.value}:\n",
        "sys/firmware/acpi/tables/APIC": acpi_table(b"APIC", b"\x01\x02"),
        "sys/firmware/acpi/tables/FACP": acpi_table(b"FACP"),
        "sys/firmware/acpi/tables/dynamic/SSDT1": acpi_table(b"SSDT"),
        "sys/firmware/acpi/tables/data/BERT": b"error record payload, not a table",
        "proc/sys/kernel/osrelease": "6.1.0-synthetic\n",
        "proc/sys/kernel/version": "#1 SMP Synthetic\n",
        "proc/sys/kernel/hostname": f"{guest.value}-guest\n",
        "proc/sys/kernel/random/boot_id": "11111111-2222-4333-8444-555555555555\n",
        "proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/mapper/root ro quiet\n",
        "etc/machine-id": f"{MACHINE_ID}\n",
        "var/lib/dbus/machine-id": f"{MACHINE_ID}\n",
        "proc/cpuinfo": (
            "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Example CPU\nmicrocode\t: 0x1\n"
            "flags\t\t: fpu sse2 hypervisor\nbugs\t\t: spectre_v1\n\n"
            "processor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Example CPU\nmicrocode\t: 0x1\n"
            "flags\t\t: fpu sse2 hypervisor\nbugs\t\t: spectre_v1\n\n"
        ),
        "sys/devices/system/cpu/online": "0-1\n",
        "sys/devices/system/cpu/possible": "0-1\n",
        "sys/devices/system/cpu/present": "0-1\n",
        "sys/devices/system/cpu/kernel_max": "8191\n",
        "sys/devices/system/cpu/smt/active": "0\n",
        "sys/devices/system/cpu/vulnerabilities/meltdown": "Not affected\n",
        "sys/devices/system/cpu/vulnerabilities/spectre_v2": "Mitigation: Enhanced IBRS\n",
        **{f"sys/devices/system/cpu/cpu{n}/topology/core_id": f"{n}\n" for n in (0, 1)},
        **{f"sys/devices/system/cpu/cpu{n}/topology/physical_package_id": "0\n" for n in (0, 1)},
        **{f"sys/devices/system/cpu/cpu{n}/cache/index0/level": "1\n" for n in (0, 1)},
        **{f"sys/devices/system/cpu/cpu{n}/cache/index0/size": "48K\n" for n in (0, 1)},
        **{f"sys/devices/system/cpu/cpu{n}/cache/index1/level": "2\n" for n in (0, 1)},
        **{f"sys/devices/system/cpu/cpu{n}/cache/index1/size": "2048K\n" for n in (0, 1)},
        "sys/devices/system/cpu/cpu1/online": "1\n",
        "proc/meminfo": "MemTotal:        4096000 kB\nMemFree:         1024000 kB\nHugePages_Total:       0\n",
        "sys/devices/system/memory/block_size_bytes": "8000000\n",
        "sys/devices/system/memory/auto_online_blocks": "online\n",
        "sys/devices/system/memory/memory0/state": "online\n",
        "sys/devices/system/memory/memory1/state": "online\n",
        "sys/devices/system/node/node0/cpulist": "0-1\n",
        "sys/devices/system/node/node0/distance": "10\n",
        "sys/devices/system/node/node0/meminfo": "Node 0 MemTotal:       4096000 kB\nNode 0 MemFree: 1 kB\n",
        "sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages": "0\n",
        "sys/kernel/mm/hugepages/hugepages-2048kB/nr_overcommit_hugepages": "0\n",
        "sys/kernel/mm/transparent_hugepage/enabled": "always [madvise] never\n",
        "sys/kernel/security/lockdown": "[none] integrity confidentiality\n",
        "sys/block/dm-0/dm/name": "root\n",
        "sys/block/dm-0/dm/uuid": f"CRYPT-LUKS2-{luks_hex}-root\n",
        "sys/block/dm-0/dm/suspended": "0\n",
        "sys/block/dm-0/slaves/sda3/dev": "8:3\n",
        "dev/sda3": _luks2_header(),
        "sys/block/dm-1/dm/name": "vg0-swap\n",
        "sys/block/dm-1/dm/uuid": "LVM-" + "A" * 32 + "B" * 32 + "\n",
        "proc/modules": "nf_tables 372736 1 nft_ct, Live 0x0\nx_tables 65536 0 - Live 0x0\n",
        "proc/1/comm": "systemd\n",
    }


def _vmware_files() -> dict[str, str | bytes]:
    return {
        "sys/class/dmi/id/sys_vendor": "VMware, Inc.\n",
        "sys/class/dmi/id/product_name": "VMware Virtual Platform\n",
        "sys/firmware/acpi/tables/MSDM": acpi_table(b"MSDM", bytes(20) + PLANTED_KEY.encode()),
        f"sys/firmware/efi/efivars/SecureBoot-{_EFI_GLOBAL}": _efivar(1),
        f"sys/firmware/efi/efivars/SetupMode-{_EFI_GLOBAL}": _efivar(0),
        f"sys/firmware/efi/efivars/MokListRT-{_SHIM}": _efivar(0),
        "sys/devices/system/clocksource/clocksource0/current_clocksource": "tsc\n",
        "sys/devices/system/clocksource/clocksource0/available_clocksource": "tsc hpet acpi_pm\n",
        "sys/class/tpm/tpm0/tpm_version_major": "2\n",
        "sys/class/tpm/tpm0/device/description": "TPM 2.0 Device\n",
        "sys/class/tpm/tpm0/device/hid": "MSFT0101\n",
        "sys/kernel/security/lsm": "lockdown,capability,yama,apparmor\n",
        "sys/module/apparmor/parameters/enabled": "Y\n",
        "sys/kernel/security/apparmor/profiles": "/usr/bin/a (enforce)\n/usr/bin/b (complain)\n/usr/bin/c (enforce)\n",
        "usr/lib/systemd/system/open-vm-tools.service": "[Unit]\n",
        "usr/lib/systemd/system/vgauth.service": "[Unit]\n",
        "etc/systemd/system/multi-user.target.wants/open-vm-tools.service": "[Unit]\n",
        "proc/42/comm": "vmtoolsd\n",
    }


def _kvm_files() -> dict[str, str | bytes]:
    return {
        "sys/class/dmi/id/sys_vendor": "QEMU\n",
        "sys/class/dmi/id/product_name": "Standard PC (Q35 + ICH9, 2009)\n",
        "sys/devices/system/clocksource/clocksource0/current_clocksource": "kvm-clock\n",
        "sys/devices/system/clocksource/clocksource0/available_clocksource": "kvm-clock tsc acpi_pm\n",
        "sys/kernel/security/lsm": "lockdown,capability,yama,selinux\n",
        "sys/fs/selinux/enforce": "1\n",
        "sys/fs/selinux/policyvers": "33\n",
        "usr/lib/systemd/system/qemu-guest-agent.service": "[Unit]\n",
        "usr/lib/systemd/system/cloud-init.service": "[Unit]\n",
        "var/lib/cloud/data/instance-id": "i-synthetic01\n",
        "proc/77/comm": "qemu-ga\n",
        "proc/88/comm": "python3\n",
        "proc/88/cmdline": b"/usr/bin/python3\0/usr/bin/cloud-init\0init\0",
    }


def write_system_tree(root: Path, guest: Guest) -> Path:
    """Write the guest's system files under ``root`` (over any already there) and return ``root``."""
    files = {**_common_files(guest), **(_vmware_files() if guest is Guest.VMWARE else _kvm_files())}
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        # Bytes, not write_text: on Windows write_text turns each newline into CRLF.
        target.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    (root / "sys/hypervisor").mkdir(parents=True, exist_ok=True)
    return root


def system_answers(guest: Guest) -> JsonObject:
    """Return the guest's non-file answers: CPUID, and for the VMware-like guest its EK certificate."""
    if guest is Guest.VMWARE:
        return {**linux_answers(hypervisor=b"VMwareVMware"), "tpm_nv": {EK_INDEX: ek_certificate_der().hex()}}
    return linux_answers(hypervisor=b"KVMKVMKVM")


__all__ = ["EK_INDEX", "LUKS_UUID", "MACHINE_ID", "Guest", "system_answers", "write_system_tree"]
