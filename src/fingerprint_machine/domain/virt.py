"""Which hypervisor a machine runs under, decided from what the machine itself shows.

The same question ``systemd-detect-virt --vm`` answers, answered from the same two signals without
running it: the DMI strings the firmware publishes (vendor and product names) and the CPUID
hypervisor leaf (``0x40000000``, a 12-byte vendor signature) plus the hypervisor-present bit
(leaf 1, ECX bit 31). They are weighed in systemd's order: a DMI string naming Oracle, Xen, Amazon
or Google decides at once (it names the product where CPUID names only the hypervisor underneath);
then a known CPUID vendor (a KVM guest's DMI says ``QEMU``, its CPUID says ``KVMKVMKVM``: kvm);
then any other DMI match; then the hypervisor-present bit alone.

Contents:
    * :class:`VirtKind` - the verdicts.
    * :class:`VirtVerdict` - a verdict and the signal it came from.
    * :data:`DMI_FIELDS` - the ``/sys/class/dmi/id`` files consulted, in order.
    * :func:`detect_virt` - decide.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .json_types import JsonObject


class VirtKind(StrEnum):
    """What the machine runs on, in systemd-detect-virt's words where it has one."""

    NONE = "none"
    UNKNOWN = "unknown"
    OTHER = "vm-other"
    KVM = "kvm"
    QEMU = "qemu"
    VMWARE = "vmware"
    MICROSOFT = "microsoft"
    ORACLE = "oracle"
    XEN = "xen"
    BOCHS = "bochs"
    PARALLELS = "parallels"
    BHYVE = "bhyve"
    QNX = "qnx"
    ACRN = "acrn"
    AMAZON = "amazon"
    GOOGLE = "google"
    APPLE = "apple"


#: The DMI files asked, in the order systemd asks them.
DMI_FIELDS = ("product_name", "sys_vendor", "board_vendor", "bios_vendor", "product_version")

# Prefixes of a DMI string, matched in this order (the more specific first).
_DMI_PREFIXES: tuple[tuple[str, VirtKind], ...] = (
    ("KVM", VirtKind.KVM),
    ("OpenStack", VirtKind.KVM),
    ("KubeVirt", VirtKind.KVM),
    ("Amazon EC2", VirtKind.AMAZON),
    ("Google Compute Engine", VirtKind.GOOGLE),
    ("QEMU", VirtKind.QEMU),
    ("VMware", VirtKind.VMWARE),
    ("VMW", VirtKind.VMWARE),
    ("innotek GmbH", VirtKind.ORACLE),
    ("VirtualBox", VirtKind.ORACLE),
    ("Oracle Corporation", VirtKind.ORACLE),
    ("Xen", VirtKind.XEN),
    ("Bochs", VirtKind.BOCHS),
    ("Parallels", VirtKind.PARALLELS),
    ("BHYVE", VirtKind.BHYVE),
    ("Hyper-V", VirtKind.MICROSOFT),
    ("Apple Virtualization", VirtKind.APPLE),
)

# The CPUID 0x40000000 vendor signatures, trailing NULs stripped.
_CPUID_VENDORS: Mapping[str, VirtKind] = {
    "XenVMMXenVMM": VirtKind.XEN,
    "KVMKVMKVM": VirtKind.KVM,
    "Linux KVM Hv": VirtKind.KVM,
    "TCGTCGTCGTCG": VirtKind.QEMU,
    "VMwareVMware": VirtKind.VMWARE,
    "Microsoft Hv": VirtKind.MICROSOFT,
    "bhyve bhyve": VirtKind.BHYVE,
    "QNXQVMBSQG": VirtKind.QNX,
    "ACRNACRNACRN": VirtKind.ACRN,
    "Apple VZ": VirtKind.APPLE,
}

# The DMI verdicts that win over CPUID (systemd: the product runs on a hypervisor CPUID names).
_DMI_DECIDES = frozenset({VirtKind.ORACLE, VirtKind.XEN, VirtKind.AMAZON, VirtKind.GOOGLE})

# Hyper-V names itself only by vendor and product together.
_HYPER_V = ("Microsoft Corporation", "Virtual Machine")


@dataclass(frozen=True)
class VirtVerdict:
    """A verdict, which signal decided it, and the value that matched."""

    kind: VirtKind
    source: str
    matched: str | None

    def as_json(self) -> JsonObject:
        """Return the verdict as JSON."""
        return {"kind": self.kind.value, "source": self.source, "matched": self.matched}


def _from_dmi(dmi: Mapping[str, str]) -> VirtVerdict | None:
    for field in DMI_FIELDS:
        value = dmi.get(field, "")
        for prefix, kind in _DMI_PREFIXES:
            if value.startswith(prefix):
                return VirtVerdict(kind, f"dmi {field}", value)
    if (dmi.get("sys_vendor"), dmi.get("product_name")) == _HYPER_V:
        return VirtVerdict(VirtKind.MICROSOFT, "dmi sys_vendor", _HYPER_V[0])
    return None


def detect_virt(*, cpuid_vendor: str | None, hypervisor_bit: bool | None, dmi: Mapping[str, str]) -> VirtVerdict:
    """Decide what the machine runs on.

    Args:
        cpuid_vendor: the CPUID ``0x40000000`` signature, or None when it was not read.
        hypervisor_bit: CPUID leaf 1 ECX bit 31, or None when it was not read.
        dmi: the readable :data:`DMI_FIELDS` values, by file name.

    Returns:
        A DMI match for Oracle, Xen, Amazon or Google; else the CPUID vendor; else any DMI match;
        else ``vm-other`` when the hypervisor bit is set with an unknown vendor; else ``none`` when
        CPUID was read; else ``unknown``.

    Example:
        >>> detect_virt(cpuid_vendor="KVMKVMKVM", hypervisor_bit=True, dmi={}).kind.value
        'kvm'
    """
    by_dmi = _from_dmi(dmi)
    if by_dmi is not None and by_dmi.kind in _DMI_DECIDES:
        return by_dmi
    known = _CPUID_VENDORS.get((cpuid_vendor or "").rstrip("\0 "))
    if known is not None:
        return VirtVerdict(known, "cpuid 0x40000000", cpuid_vendor)
    if by_dmi is not None:
        return by_dmi
    if hypervisor_bit:
        return VirtVerdict(VirtKind.OTHER, "cpuid hypervisor bit", cpuid_vendor)
    if hypervisor_bit is None:
        return VirtVerdict(VirtKind.UNKNOWN, "no signal read", None)
    return VirtVerdict(VirtKind.NONE, "cpuid hypervisor bit", None)


__all__ = ["DMI_FIELDS", "VirtKind", "VirtVerdict", "detect_virt"]
