"""Pure helpers that turn raw Windows answers into identity values.

Contents:
    * :func:`instance_serial` - the serial number part of a PnP instance id.
    * :func:`vmware_pvscsi_sas_wwid` - a VMware PVSCSI controller's sasWWID from its PCI serial.
    * :func:`mask_product_keys` - replace every product key in a JSON tree by its last 5 characters.
    * :func:`withhold_registry_values` - drop registry values that encode a product key.
    * :func:`machine_sid` - the machine SID from local account SIDs.
    * :func:`decode_tbs_device_info` - the TPM device info TBS returns.
    * :func:`decode_acpi_header` - the 36-byte header every ACPI table starts with.
    * :func:`msdm_product_key` - the masked product key an ACPI MSDM table carries.
"""

from __future__ import annotations

import re
import struct
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from .json_types import JsonObject, JsonValue

# A Windows product key: five groups of five characters from the key alphabet (letters and
# digits; real keys leave out vowels and look-alikes, but matching more is the safe direction).
_PRODUCT_KEY = re.compile(r"\b[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}\b", re.IGNORECASE)
_KEY_TAIL = 5

#: Registry values that hold a product key in an encoded, binary form a pattern cannot see.
#: DigitalProductId decodes to the installed key on many Windows versions.
WITHHELD_VALUE_NAMES = frozenset({"DigitalProductId", "DigitalProductId4"})
WITHHELD = "<withheld: encodes the product key>"

# VMware PVSCSI: PCI vendor 15AD, device 07C0. Its PnP instance serial is the controller's
# sasWWID with the two 32-bit halves swapped, followed by "00" (18 hex digits).
_PVSCSI_ID = "VEN_15AD&DEV_07C0"
_PVSCSI_SERIAL = re.compile(r"^([0-9A-F]{8})([0-9A-F]{8})00$", re.IGNORECASE)

# ACPI table header (ACPI 6.5 section 5.2.6) and the MSDM key (Microsoft's MSDM specification:
# the key string starts at offset 56 and is 29 characters long).
_ACPI_HEADER = struct.Struct("<4sIBB6s8sI4sI")
_MSDM_KEY_OFFSET = 56
_MSDM_KEY_LENGTH = 29

# TBS TPM_DEVICE_INFO: structVersion, tpmVersion, tpmInterfaceType, tpmImpRevision (u32 each).
_TBS_DEVICE_INFO = struct.Struct("<IIII")
_TPM_VERSIONS = {1: "1.2", 2: "2.0"}
# S-1-5-21-<a>-<b>-<c>-<RID>: a local account SID has seven dashes.
_LOCAL_SID_DASHES = 7


class TpmInterface(IntEnum):
    """TPM_DEVICE_INFO.tpmInterfaceType (tbs.h)."""

    TIS = 1
    TRUSTZONE = 2
    HARDWARE = 3
    EMULATOR = 4
    SPB = 5


def instance_serial(pnp_id: object) -> str | None:
    r"""Return the instance part of a PnP id, which holds a PCI device's serial number (DSN).

    Examples:
        >>> instance_serial("PCI\\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\\000C29FFFF000001")
        '000C29FFFF000001'
        >>> instance_serial(None) is None
        True
    """
    if not isinstance(pnp_id, str) or "\\" not in pnp_id:
        return None
    return pnp_id.rsplit("\\", 1)[1]


def vmware_pvscsi_sas_wwid(pnp_id: object) -> str | None:
    r"""Return a VMware PVSCSI controller's sasWWID, read back from its PCI serial number.

    VMware builds the PVSCSI device serial from the ``sasWWID`` the VM was given, halves
    swapped; this undoes it. Any other device, or a serial without that shape, gives None.

    Examples:
        >>> vmware_pvscsi_sas_wwid("PCI\\VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02\\0123ABCD5005056000")
        '500505600123abcd'
        >>> vmware_pvscsi_sas_wwid("PCI\\VEN_8086&DEV_10D3\\0123ABCD5005056000") is None
        True
    """
    if not isinstance(pnp_id, str) or _PVSCSI_ID not in pnp_id.upper():
        return None
    serial = instance_serial(pnp_id)
    match = _PVSCSI_SERIAL.match(serial or "")
    if match is None:
        return None
    return (match.group(2) + match.group(1)).lower()


def _mask_key(match: re.Match[str]) -> str:
    return "*****-*****-*****-*****-" + match.group(0)[-_KEY_TAIL:]


def mask_product_keys(value: JsonValue) -> JsonValue:
    """Return ``value`` with every product key in every string replaced by its last 5 characters.

    The last five are what Windows itself shows as the partial key, so nothing is lost that
    Windows does not already reveal.

    Examples:
        >>> mask_product_keys({"k": ["AB1CD-EF2GH-IJ3KL-MN4OP-QR5ST is set"]})
        {'k': ['*****-*****-*****-*****-QR5ST is set']}
        >>> mask_product_keys(7)
        7
    """
    if isinstance(value, str):
        return _PRODUCT_KEY.sub(_mask_key, value)
    if isinstance(value, list):
        return [mask_product_keys(v) for v in value]
    if isinstance(value, dict):
        return {k: mask_product_keys(v) for k, v in value.items()}
    return value


def withhold_registry_values(values: Mapping[str, JsonValue]) -> JsonObject:
    """Return the registry values with the ones that encode a product key withheld.

    Examples:
        >>> withhold_registry_values({"ProductId": "00000-1", "DigitalProductId": "a4000000"})
        {'ProductId': '00000-1', 'DigitalProductId': '<withheld: encodes the product key>'}
    """
    return {name: WITHHELD if name in WITHHELD_VALUE_NAMES else data for name, data in values.items()}


def machine_sid(account_sids: Iterable[object]) -> str | None:
    """Return the machine SID: the local account SIDs without their last part (the RID).

    Every local account SID is ``<machine SID>-<RID>``; the first well-formed one decides.

    Examples:
        >>> machine_sid(["S-1-5-21-111-222-333-500", "S-1-5-21-111-222-333-1001"])
        'S-1-5-21-111-222-333'
        >>> machine_sid(["S-1-5-18", None]) is None
        True
    """
    for sid in account_sids:
        if isinstance(sid, str) and sid.startswith("S-1-5-21-") and sid.count("-") >= _LOCAL_SID_DASHES:
            return sid.rsplit("-", 1)[0]
    return None


def _interface_name(value: int) -> str:
    try:
        return TpmInterface(value).name
    except ValueError:
        return f"unknown({value})"


def decode_tbs_device_info(raw: bytes) -> JsonObject:
    """Decode the TPM_DEVICE_INFO structure ``Tbsi_GetDeviceInfo`` fills.

    Examples:
        >>> decode_tbs_device_info(struct.pack("<IIII", 1, 2, 3, 0x4321))
        {'struct_version': 1, 'tpm_version': '2.0', 'interface': 'HARDWARE', 'implementation_revision': 17185}
        >>> decode_tbs_device_info(b"")
        {'error': 'TPM_DEVICE_INFO is 0 bytes, expected 16'}
    """
    if len(raw) < _TBS_DEVICE_INFO.size:
        return {"error": f"TPM_DEVICE_INFO is {len(raw)} bytes, expected {_TBS_DEVICE_INFO.size}"}
    struct_version, version, interface, revision = _TBS_DEVICE_INFO.unpack_from(raw)
    return {
        "struct_version": struct_version,
        "tpm_version": _TPM_VERSIONS.get(version, f"unknown({version})"),
        "interface": _interface_name(interface),
        "implementation_revision": revision,
    }


def _ascii(raw: bytes) -> str:
    return raw.decode("ascii", errors="replace").rstrip("\0 ")


def decode_acpi_header(table: bytes) -> JsonObject:
    """Decode the header every ACPI table starts with.

    Examples:
        >>> hdr = struct.pack("<4sIBB6s8sI4sI", b"FACP", 276, 6, 0, b"OEMID ", b"TABLEID ", 1, b"ACPI", 2)
        >>> decode_acpi_header(hdr)["oem_id"], decode_acpi_header(hdr)["oem_table_id"]
        ('OEMID', 'TABLEID')
        >>> decode_acpi_header(b"FACP")
        {'error': 'ACPI table is 4 bytes, shorter than its 36-byte header'}
    """
    if len(table) < _ACPI_HEADER.size:
        return {"error": f"ACPI table is {len(table)} bytes, shorter than its {_ACPI_HEADER.size}-byte header"}
    sig, length, rev, checksum, oem, oem_table, oem_rev, creator, creator_rev = _ACPI_HEADER.unpack_from(table)
    return {
        "signature": _ascii(sig),
        "length": length,
        "revision": rev,
        "checksum": checksum,
        "oem_id": _ascii(oem),
        "oem_table_id": _ascii(oem_table),
        "oem_revision": oem_rev,
        "creator_id": _ascii(creator),
        "creator_revision": creator_rev,
    }


def msdm_product_key(table: bytes) -> JsonObject:
    """Return whether an MSDM table carries a product key, and the key masked to its last 5.

    Examples:
        >>> body = b"MSDM" + bytes(52) + b"AB1CD-EF2GH-IJ3KL-MN4OP-QR5ST"
        >>> msdm_product_key(body)
        {'present': True, 'product_key': '*****-*****-*****-*****-QR5ST'}
        >>> msdm_product_key(b"MSDM")
        {'present': False, 'product_key': None}
    """
    raw = table[_MSDM_KEY_OFFSET : _MSDM_KEY_OFFSET + _MSDM_KEY_LENGTH]
    key = _ascii(raw)
    if not _PRODUCT_KEY.fullmatch(key):
        return {"present": False, "product_key": None}
    return {"present": True, "product_key": mask_product_keys(key)}


__all__ = [
    "WITHHELD",
    "WITHHELD_VALUE_NAMES",
    "TpmInterface",
    "decode_acpi_header",
    "decode_tbs_device_info",
    "instance_serial",
    "machine_sid",
    "mask_product_keys",
    "msdm_product_key",
    "vmware_pvscsi_sas_wwid",
]
