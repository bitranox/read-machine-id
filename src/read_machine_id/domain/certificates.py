"""Read the certificates Windows keeps in a registry certificate store.

The TPM's endorsement key (EK) certificates, among others, sit under a registry store key with
one subkey per certificate (named by its SHA-1 thumbprint) holding a ``Blob`` value. The blob is
a run of property records, each ``property id (u32), reserved (u32), length (u32), data``; the
record with id 32 (``CERT_CERT_PROP_ID``) carries the DER-encoded certificate. Only public
certificate fields are returned; a certificate holds no private material.

Contents:
    * :func:`der_from_store_blob` - the DER certificate inside a store blob.
    * :func:`describe_certificate` - the public fields of a DER certificate.
"""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

from cryptography import x509

if TYPE_CHECKING:
    from .json_types import JsonObject

_RECORD = struct.Struct("<III")
CERT_CERT_PROP_ID = 32


def der_from_store_blob(blob: bytes) -> bytes | None:
    """Return the DER certificate a registry store blob carries, or None when it has none.

    Examples:
        >>> rec = struct.pack("<III", 3, 1, 2) + b"xy" + struct.pack("<III", 32, 1, 3) + b"DER"
        >>> der_from_store_blob(rec)
        b'DER'
        >>> der_from_store_blob(b"\\x01") is None
        True
    """
    pos = 0
    while pos + _RECORD.size <= len(blob):
        prop_id, _reserved, length = _RECORD.unpack_from(blob, pos)
        start = pos + _RECORD.size
        if start + length > len(blob):
            return None
        if prop_id == CERT_CERT_PROP_ID:
            return blob[start : start + length]
        pos = start + length
    return None


def describe_certificate(der: bytes) -> JsonObject:
    """Return the public fields of a DER certificate, or an error when it does not parse.

    Examples:
        >>> describe_certificate(b"not a certificate")["error"].startswith("not a DER certificate")
        True
    """
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        return {"error": f"not a DER certificate: {exc}"}
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha1": hashlib.sha1(der, usedforsecurity=False).hexdigest().upper(),
        "sha256": hashlib.sha256(der).hexdigest().upper(),
    }


__all__ = ["CERT_CERT_PROP_ID", "der_from_store_blob", "describe_certificate"]
