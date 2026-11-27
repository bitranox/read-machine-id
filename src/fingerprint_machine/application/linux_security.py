"""The ``security`` section of a Linux reading: firmware trust, the TPM, kernel hardening, encryption.

The same questions the Windows section answers, under the same keys where the value is the same
thing (``firmware_type``, ``secure_boot``, ``tpm``, ``ek_certificates``):

* firmware type and Secure Boot from the UEFI variables (``SecureBoot``, ``SetupMode``), and
  whether shim's Secure Boot validation was turned off (``MokSBStateRT``);
* the TPM as sysfs describes it, and its EK certificates read from the TPM's NV indices
  (``0x01C00002`` RSA, ``0x01C0000A`` ECC) through ``/dev/tpmrm0``, public fields only. The
  device is ``root:tss``: unprivileged, the certificates record ``NeedsRootError``;
* kernel lockdown, the active LSMs, SELinux and AppArmor state (profile counts per mode, never
  the profile names), IMA;
* device-mapper volumes: dm-crypt (with the LUKS header's version, cipher and UUID, read as root,
  never a key slot) and LVM;
* whether a firewall can be in force: the netfilter modules loaded.

Contents:
    * :data:`EK_CERTIFICATE_INDICES` - the NV indices EK certificates sit in.
    * :func:`read_linux_security` - the section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.certificates import describe_certificate
from ..domain.devmapper import DmKind, classify_dm_uuid
from ..domain.efivars import EFI_GLOBAL, EFIVARS, SHIM_LOCK, FirmwareType, decode_efivar_flag, efivar_path
from ..domain.luks import LUKS_PROBE_BYTES, decode_luks_header, luks_header_size
from ..domain.machine_errors import MissingPathError, SourceError
from ..domain.procfs import parse_apparmor_modes, parse_choice, parse_module_names
from ..domain.tpm2 import TpmResponseError
from .guard import guarded
from .linux_files import file_values, item_section, optional_dir, optional_text, text

if TYPE_CHECKING:
    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

#: The TCG EK credential profile's NV indices: RSA 2048 and ECC NIST P-256 EK certificates.
EK_CERTIFICATE_INDICES = (0x01C00002, 0x01C0000A)
_EFI = "/sys/firmware/efi"
_TPM_CLASS = "/sys/class/tpm"
_SECURITYFS = "/sys/kernel/security"
_SELINUX = "/sys/fs/selinux"
_EFIVAR_MAX = 64
_FIREWALL_MODULES = frozenset(
    {
        "nf_tables",
        "x_tables",
        "ip_tables",
        "ip6_tables",
        "iptable_filter",
        "ip6table_filter",
        "iptable_nat",
        "nft_compat",
        "ebtables",
        "arp_tables",
    }
)


def _firmware_type(src: LinuxSource) -> FirmwareType:
    return FirmwareType.UEFI if optional_dir(src, _EFI) else FirmwareType.BIOS


def _flag(src: LinuxSource, name: str, guid: str) -> int:
    return int(decode_efivar_flag(src.read_bytes(efivar_path(name, guid), max_bytes=_EFIVAR_MAX)))


def _efivar_names(src: LinuxSource) -> set[str]:
    """The UEFI variables visible; refuse when there are none (efivarfs not mounted here)."""
    names = set(src.list_dir(EFIVARS))
    if not names:
        msg = f"{EFIVARS}: no UEFI variables visible (efivarfs is not mounted)"
        raise SourceError(msg)
    return names


def _secure_boot(src: LinuxSources) -> JsonValue:
    # Named as Windows names them (HKLM\...\SecureBoot\State), 0 or 1, so the two compare.
    if _firmware_type(src.system) is FirmwareType.BIOS:
        return None
    _efivar_names(src.system)
    return {
        "UEFISecureBootEnabled": guarded(lambda: _flag(src.system, "SecureBoot", EFI_GLOBAL)),
        "SetupMode": guarded(lambda: _flag(src.system, "SetupMode", EFI_GLOBAL)),
    }


def _mok(src: LinuxSources) -> JsonValue:
    if _firmware_type(src.system) is FirmwareType.BIOS:
        return None
    names = _efivar_names(src.system)
    state = f"MokSBStateRT-{SHIM_LOCK}"
    disabled = guarded(lambda: _flag(src.system, "MokSBStateRT", SHIM_LOCK)) if state in names else False
    return {"validation_disabled": disabled, "mok_list_present": f"MokListRT-{SHIM_LOCK}" in names}


def _driver_name(src: LinuxSource, link: str) -> str | None:
    try:
        return src.readlink(link).rsplit("/", 1)[-1]
    except MissingPathError:
        return None  # no driver bound


def _tpm_device(src: LinuxSource, name: str) -> JsonObject:
    base = f"{_TPM_CLASS}/{name}"
    driver = guarded(lambda: _driver_name(src, f"{base}/device/driver"))
    return {
        "name": name,
        **file_values(src, base, ("tpm_version_major",)),
        **file_values(src, f"{base}/device", ("description", "hid", "caps")),
        "ppi_version": guarded(lambda: optional_text(src, f"{base}/ppi/version")),
        "driver": driver,
    }


def _tpm(src: LinuxSources) -> JsonValue:
    names = [n for n in optional_dir(src.system, _TPM_CLASS) if n.startswith("tpm")]
    devices: list[JsonValue] = [guarded(lambda name=name: _tpm_device(src.system, name)) for name in names]
    return devices


def _ek_certificate(src: LinuxSource, index: int) -> JsonObject | None:
    try:
        der = src.tpm_nv_read(index)
    except TpmResponseError as exc:
        if exc.index_undefined:
            return None
        raise
    return {"nv_index": f"0x{index:08x}", **describe_certificate(der)}


def _ek_certificates(src: LinuxSources) -> JsonValue:
    # No TPM in sysfs: nothing to read. A TPM whose device cannot be opened is an error.
    if not optional_dir(src.system, _TPM_CLASS):
        return []
    found: list[JsonValue] = []
    for index in EK_CERTIFICATE_INDICES:
        certificate = _ek_certificate(src.system, index)
        if certificate is not None:
            found.append(certificate)
    return found


def _lockdown(src: LinuxSources) -> JsonValue:
    value = optional_text(src.system, f"{_SECURITYFS}/lockdown")
    return None if value is None else parse_choice(value)


def _lsm(src: LinuxSources) -> JsonValue:
    value = optional_text(src.system, f"{_SECURITYFS}/lsm")
    names: list[JsonValue] = [] if value is None else [n for n in value.split(",") if n]
    return names


def _selinux(src: LinuxSources) -> JsonValue:
    if not optional_dir(src.system, _SELINUX):
        return None
    return file_values(src.system, _SELINUX, ("enforce", "policyvers", "mls", "deny_unknown"))


def _apparmor(src: LinuxSources) -> JsonValue:
    enabled = optional_text(src.system, "/sys/module/apparmor/parameters/enabled")
    if enabled is None:
        return None
    profiles = guarded(lambda: parse_apparmor_modes(text(src.system, f"{_SECURITYFS}/apparmor/profiles")))
    return {"enabled": enabled, "profiles_by_mode": profiles}


def _ima(src: LinuxSources) -> JsonValue:
    base = f"{_SECURITYFS}/ima"
    if not optional_dir(src.system, base):
        return None
    return {"present": True, **file_values(src.system, base, ("runtime_measurements_count",))}


def _luks(src: LinuxSource, slave: str) -> JsonValue:
    device = f"/dev/{slave}"
    probe = src.read_prefix(device, size=LUKS_PROBE_BYTES)
    size = luks_header_size(probe)
    header = probe if size <= len(probe) else src.read_prefix(device, size=size)
    return decode_luks_header(header)


def _dm_device(src: LinuxSource, name: str) -> JsonObject:
    base = f"/sys/block/{name}"
    uuid = optional_text(src, f"{base}/dm/uuid") or ""
    target = classify_dm_uuid(uuid)
    slaves = optional_dir(src, f"{base}/slaves")
    slave_names: list[JsonValue] = list(slaves)
    record: JsonObject = {
        "device": name,
        **file_values(src, f"{base}/dm", ("name", "uuid", "suspended")),
        **target.as_json(),
        "slaves": slave_names,
    }
    if target.kind is DmKind.CRYPT and len(slaves) == 1:
        record["luks"] = guarded(lambda: _luks(src, slaves[0]))
    return record


def _device_mapper(src: LinuxSources) -> JsonValue:
    names = [n for n in optional_dir(src.system, "/sys/block") if n.startswith("dm-")]
    devices: list[JsonValue] = [guarded(lambda name=name: _dm_device(src.system, name)) for name in names]
    return devices


def _firewall(src: LinuxSources) -> JsonValue:
    loaded = sorted(set(parse_module_names(text(src.system, "/proc/modules"))) & _FIREWALL_MODULES)
    modules: list[JsonValue] = list(loaded)
    return {
        "modules": modules,
        "nftables": "nf_tables" in loaded,
        "iptables": any(m in loaded for m in ("ip_tables", "ip6_tables")),
    }


def read_linux_security(src: LinuxSources) -> JsonValue:
    """Read the ``security`` section, each item guarded."""
    return item_section(
        src,
        {
            "firmware_type": lambda s: _firmware_type(s.system).value,
            "secure_boot": _secure_boot,
            "mok": _mok,
            "tpm": _tpm,
            "ek_certificates": _ek_certificates,
            "lockdown": _lockdown,
            "lsm": _lsm,
            "selinux": _selinux,
            "apparmor": _apparmor,
            "ima": _ima,
            "device_mapper": _device_mapper,
            "firewall": _firewall,
        },
    )


__all__ = ["EK_CERTIFICATE_INDICES", "read_linux_security"]
