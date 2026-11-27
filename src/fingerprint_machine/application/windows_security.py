r"""The ``security`` section of a Windows reading: the machine's security posture, item by item.

What a Linux reading records under ``secure_boot``, ``tpm``, ``firewall`` and ``lockdown``-like
keys, Windows keeps in CIM classes and policy keys: Secure Boot state, policy and servicing;
the TPM (``Win32_Tpm``, TBS, the TPM service's own registry values); BitLocker per volume;
Virtualization-based security (``Win32_DeviceGuard``); LSA protection (``RunAsPPL``); Kernel DMA
Protection; Microsoft Defender; the firewall profiles; UAC; SmartScreen; Windows Update policy and
results; Windows Hello for Business policy and the credential providers.

A policy key exists only where a policy was set: its absence is recorded as None (nothing
configured), not as an error.

Two things a reading never carries: BitLocker recovery material and protector ids (protectors are
recorded by type only), and TPM authorization values (withheld if Windows cached one in the
registry).

``Win32_EncryptableVolume`` and ``Win32_Tpm`` answer some values only through methods (lock state,
encryption percentage, key protectors, readiness, ownership, the lockout state): each volume and
the TPM carry those under ``methods`` (see :mod:`.windows_cim_methods`).

Contents:
    * :data:`SECURITY_READERS` - the section's items.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.certificates import der_from_store_blob, describe_certificate
from ..domain.identity import decode_tbs_device_info, withhold_tpm_authorization
from .guard import guarded
from .windows_cim_methods import bitlocker_volumes, tpm_with_methods
from .windows_values import cim, optional_reg, optional_subkeys, optional_values, reg, values

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import WindowsSources
    from .windows_values import Reader

_DEVICE_GUARD = "root/Microsoft/Windows/DeviceGuard"
_DEFENDER = "root/Microsoft/Windows/Defender"
_STANDARD = "root/StandardCimv2"
_CONTROL = r"HKLM\SYSTEM\CurrentControlSet\Control"
_POLICIES = r"HKLM\SOFTWARE\Policies\Microsoft"
_CURRENT_VERSION = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"
_SECURE_BOOT = rf"{_CONTROL}\SecureBoot"
_CREDENTIAL_PROVIDERS = rf"{_CURRENT_VERSION}\Authentication\Credential Providers"
_EK_STORE = r"HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\EKCertStore\Certificates"
_UPDATE_RESULTS = rf"{_CURRENT_VERSION}\WindowsUpdate\Auto Update\Results"


def _ek_certificates(src: WindowsSources) -> JsonValue:
    out: list[JsonValue] = []
    # The store exists only once Windows has cached an EK certificate (a TPM that has one).
    for thumb in optional_subkeys(src, _EK_STORE):
        blob = src.registry.values(rf"{_EK_STORE}\{thumb}").get("Blob")
        der = der_from_store_blob(blob) if isinstance(blob, bytes) else None
        detail = describe_certificate(der) if der is not None else {"error": "no certificate in the store blob"}
        out.append({"store_thumbprint": thumb, **detail})
    return out


def _tbs(src: WindowsSources) -> JsonValue:
    return decode_tbs_device_info(src.platform.tbs_device_info())


def _tpm_service(src: WindowsSources) -> JsonValue:
    # Only the key's own values: its Admin subkey is where Windows can cache owner authorization.
    found = optional_values(src, r"HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI")
    return None if found is None else withhold_tpm_authorization(found)


def _credential_providers(src: WindowsSources) -> JsonValue:
    out: list[JsonValue] = []
    for clsid in optional_subkeys(src, _CREDENTIAL_PROVIDERS):
        name = guarded(lambda clsid=clsid: values(src, rf"{_CREDENTIAL_PROVIDERS}\{clsid}").get(""))
        out.append({"clsid": clsid, "name": name})
    return out


def _smartscreen(src: WindowsSources) -> JsonValue:
    explorer = optional_values(src, rf"{_CURRENT_VERSION}\Explorer")
    return {
        "explorer": explorer.get("SmartScreenEnabled") if explorer is not None else None,
        "policy": optional_values(src, rf"{_POLICIES}\Windows\System"),
        "edge_policy": optional_values(src, rf"{_POLICIES}\Edge"),
    }


def _windows_update(src: WindowsSources) -> JsonValue:
    results: JsonObject = {
        phase: guarded(lambda phase=phase: optional_values(src, rf"{_UPDATE_RESULTS}\{phase}"))
        for phase in ("Detect", "Download", "Install")
    }
    return {
        "policy": optional_values(src, rf"{_POLICIES}\Windows\WindowsUpdate"),
        "policy_au": optional_values(src, rf"{_POLICIES}\Windows\WindowsUpdate\AU"),
        "settings": optional_values(src, r"HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"),
        "results": results,
    }


def _kernel_dma_protection(src: WindowsSources) -> JsonValue:
    return {
        "enabled": src.platform.kernel_dma_protection(),
        "policy": optional_values(src, rf"{_POLICIES}\Windows\Kernel DMA Protection"),
    }


#: The security section's items, each asked and guarded on its own.
SECURITY_READERS: Mapping[str, Reader] = {
    "firmware_type": lambda src: src.platform.firmware_type(),
    "secure_boot": reg(rf"{_SECURE_BOOT}\State"),
    "secure_boot_config": optional_reg(_SECURE_BOOT),
    "secure_boot_servicing": optional_reg(rf"{_SECURE_BOOT}\Servicing"),
    "tpm": tpm_with_methods,
    "tbs": _tbs,
    "ek_certificates": _ek_certificates,
    "tpm_service": _tpm_service,
    "device_guard": cim("Win32_DeviceGuard", _DEVICE_GUARD),
    "device_guard_config": optional_reg(rf"{_CONTROL}\DeviceGuard"),
    "bitlocker": bitlocker_volumes,
    "bitlocker_policy": optional_reg(rf"{_POLICIES}\FVE"),
    "lsa": reg(rf"{_CONTROL}\Lsa"),
    "kernel_dma_protection": _kernel_dma_protection,
    "defender": cim("MSFT_MpComputerStatus", _DEFENDER),
    "firewall": cim("MSFT_NetFirewallProfile", _STANDARD),
    "uac": reg(rf"{_CURRENT_VERSION}\Policies\System"),
    "smartscreen": _smartscreen,
    "windows_update": _windows_update,
    "windows_hello": optional_reg(rf"{_POLICIES}\PassportForWork"),
    "credential_providers": _credential_providers,
}

__all__ = ["SECURITY_READERS"]
