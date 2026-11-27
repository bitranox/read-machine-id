"""The public fields of a LUKS header: version, UUID, cipher. Never a key slot.

A LUKS volume starts with a header (cryptsetup's on-disk format, LUKS1 and LUKS2). Only the fields
that say WHAT the volume is are returned: its version, UUID, label, cipher and the data segments
it maps. The key material is never read into the result: not the key slots, not the master key
digest, not the salt, not the LUKS2 ``keyslots``, ``digests`` or ``tokens`` objects.

LUKS1 is one 592-byte binary header (all integers big-endian). LUKS2 is a 4096-byte binary header
followed by a JSON area; ``hdr_size`` in the binary header covers both.

Contents:
    * :data:`LUKS_PROBE_BYTES` - how much to read first.
    * :func:`luks_header_size` - how much of the device the whole header takes.
    * :func:`decode_luks_header` - the public fields.
"""

from __future__ import annotations

import json
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject, JsonValue

_MAGIC = b"LUKS\xba\xbe"
#: Read this much first: it holds a whole LUKS1 header and the LUKS2 binary header.
LUKS_PROBE_BYTES = 4096
_LUKS1_SIZE = 592
# cryptsetup caps the LUKS2 header (binary header plus JSON area) at 4 MiB.
_LUKS2_MAX = 4 * 1024 * 1024
_VERSION = struct.Struct(">H")
_V1, _V2 = 1, 2
_LUKS1 = struct.Struct(">6sH32s32s32sII20s32sI40s")
_LUKS2 = struct.Struct(">6sHQQ48s32s64s40s48sQ")
# The segment fields that describe the mapping; anything else in a segment is left out.
_SEGMENT_FIELDS = ("type", "offset", "size", "encryption", "sector_size")


def _text(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")


def _version(raw: bytes) -> int:
    if not raw.startswith(_MAGIC) or len(raw) < len(_MAGIC) + _VERSION.size:
        msg = "not a LUKS header: no LUKS magic"
        raise ValueError(msg)
    (version,) = _VERSION.unpack_from(raw, len(_MAGIC))
    return version


def luks_header_size(probe: bytes) -> int:
    """Return how many bytes the whole header takes, from its first :data:`LUKS_PROBE_BYTES`.

    Raises:
        ValueError: no LUKS magic, an unknown version, or a LUKS2 header size out of range.

    Example:
        >>> luks_header_size(b"LUKS\\xba\\xbe\\x00\\x01" + bytes(100))
        592
    """
    version = _version(probe)
    if version == _V1:
        return _LUKS1_SIZE
    if version == _V2 and len(probe) >= _LUKS2.size:
        size = _LUKS2.unpack_from(probe)[2]
        if LUKS_PROBE_BYTES <= size <= _LUKS2_MAX:
            return size
        msg = f"LUKS2 header states {size} bytes, outside {LUKS_PROBE_BYTES}..{_LUKS2_MAX}"
        raise ValueError(msg)
    msg = f"LUKS version {version} is not one this tool reads"
    raise ValueError(msg)


def _luks1(raw: bytes) -> JsonObject:
    if len(raw) < _LUKS1.size:
        msg = f"LUKS1 header is {len(raw)} bytes, shorter than {_LUKS1.size}"
        raise ValueError(msg)
    fields = _LUKS1.unpack_from(raw)
    # fields: magic, version, cipher name, cipher mode, hash, payload offset, key bytes,
    # master key digest (left out), digest salt (left out), digest iterations (left out), uuid.
    return {
        "version": 1,
        "uuid": _text(fields[10]),
        "cipher_name": _text(fields[2]),
        "cipher_mode": _text(fields[3]),
        "hash_spec": _text(fields[4]),
        "payload_offset": fields[5],
        "key_bytes": fields[6],
    }


def _segments(area: JsonValue) -> list[JsonValue]:
    segments = area.get("segments") if isinstance(area, dict) else None
    if not isinstance(segments, dict):
        return []
    return [
        {k: seg[k] for k in _SEGMENT_FIELDS if k in seg}
        for _, seg in sorted(segments.items(), key=lambda item: item[0])
        if isinstance(seg, dict)
    ]


def _json_area(raw: bytes, size: int) -> JsonValue:
    text = raw[LUKS_PROBE_BYTES:size].split(b"\0", 1)[0]
    try:
        return json.loads(text)
    except ValueError as exc:
        msg = f"LUKS2 JSON area does not parse: {exc}"
        raise ValueError(msg) from exc


def _luks2(raw: bytes) -> JsonObject:
    size = luks_header_size(raw)
    if len(raw) < size:
        msg = f"LUKS2 header states {size} bytes, {len(raw)} given"
        raise ValueError(msg)
    fields = _LUKS2.unpack_from(raw)
    # fields: magic, version, hdr_size, seqid, label, checksum alg, salt (left out), uuid,
    # subsystem, header offset.
    return {
        "version": 2,
        "uuid": _text(fields[7]),
        "label": _text(fields[4]),
        "subsystem": _text(fields[8]),
        "checksum_alg": _text(fields[5]),
        "header_size": size,
        "segments": _segments(_json_area(raw, size)),
    }


def decode_luks_header(raw: bytes) -> JsonObject:
    """Return the public fields of a whole header (:func:`luks_header_size` bytes).

    Raises:
        ValueError: not LUKS, an unknown version, or a header shorter than it states.
    """
    version = _version(raw)
    if version == _V1:
        return _luks1(raw)
    if version == _V2:
        return _luks2(raw)
    msg = f"LUKS version {version} is not one this tool reads"
    raise ValueError(msg)


__all__ = ["LUKS_PROBE_BYTES", "decode_luks_header", "luks_header_size"]
