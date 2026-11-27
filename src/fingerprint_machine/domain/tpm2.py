"""The two TPM 2.0 commands that read a non-volatile index: NV_ReadPublic and NV_Read.

TPM 2.0 Library, Part 3, sections 31.6 (``TPM2_NV_ReadPublic``) and 31.13 (``TPM2_NV_Read``).
Commands and responses are big-endian: a 10-byte header (tag, size, command or response code),
then handles, an authorization area for a command with sessions, then parameters.

The EK certificate indices (``0x01C00002`` RSA, ``0x01C0000A`` ECC) are read with an empty password
session: as the index itself when its attributes allow ``AUTHREAD``, else as the owner when they
allow ``OWNERREAD`` (an owner with an empty auth value, the default). A TPM answers at most
``TPM_PT_NV_BUFFER_MAX`` bytes per read, so the content is read in :data:`NV_CHUNK` pieces.

Contents:
    * :class:`TpmResponseError` - the TPM answered with an error code.
    * :class:`NvPublic` - an index's public area.
    * :func:`nv_read_public_command`, :func:`parse_nv_read_public` - ask for the public area.
    * :func:`nv_read_command`, :func:`parse_nv_read` - read a piece of the content.
    * :func:`nv_read_auth` - the handle a read authorizes as.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .machine_errors import SourceError

_HEADER = struct.Struct(">HII")
_ST_NO_SESSIONS = 0x8001
_ST_SESSIONS = 0x8002
_CC_NV_READ_PUBLIC = 0x00000169
_CC_NV_READ = 0x0000014E
_RS_PW = 0x40000009
_RH_OWNER = 0x40000001
_SUCCESS = 0
# A format-1 response code with its handle/parameter number masked off (Part 2, 6.6.3).
_RC_FORMAT1_MASK = 0x0BF
_RC_HANDLE = 0x08B
# TPMA_NV bits (Part 2, 13.4).
_OWNERREAD = 1 << 17
_AUTHREAD = 1 << 18
#: Read this many bytes per NV_Read: below every TPM's TPM_PT_NV_BUFFER_MAX (at least 512 on fTPMs).
NV_CHUNK = 512
# An empty password session: handle, empty nonce, attributes 0, empty password.
_PASSWORD_SESSION = struct.pack(">IHBH", _RS_PW, 0, 0, 0)


class TpmResponseError(SourceError):
    """The TPM answered a command with a non-zero response code.

    Example:
        >>> TpmResponseError(0x18B).code
        395
    """

    def __init__(self, code: int) -> None:
        """Record the response code."""
        super().__init__(f"TPM response code 0x{code:08x}")
        self.code = code

    @property
    def index_undefined(self) -> bool:
        """True for TPM_RC_HANDLE on a handle: the NV index asked for is not defined.

        Example:
            >>> TpmResponseError(0x18B).index_undefined, TpmResponseError(0x101).index_undefined
            (True, False)
        """
        return self.code & _RC_FORMAT1_MASK == _RC_HANDLE


@dataclass(frozen=True)
class NvPublic:
    """The public area of an NV index: who may read it and how large it is."""

    index: int
    name_alg: int
    attributes: int
    data_size: int


def _command(tag: int, code: int, body: bytes) -> bytes:
    return _HEADER.pack(tag, _HEADER.size + len(body), code) + body


def _response_body(response: bytes) -> bytes:
    if len(response) < _HEADER.size:
        msg = f"TPM response is {len(response)} bytes, shorter than its header"
        raise ValueError(msg)
    _tag, size, code = _HEADER.unpack_from(response)
    if code != _SUCCESS:
        raise TpmResponseError(code)
    if size != len(response):
        msg = f"TPM response states {size} bytes, holds {len(response)}"
        raise ValueError(msg)
    return response[_HEADER.size :]


def _unpack(layout: str, data: bytes, offset: int = 0) -> tuple[int, ...]:
    try:
        return struct.unpack_from(layout, data, offset)
    except struct.error as exc:
        msg = f"TPM response too short: {exc}"
        raise ValueError(msg) from exc


def nv_read_public_command(index: int) -> bytes:
    """Return ``TPM2_NV_ReadPublic`` for ``index``.

    Example:
        >>> nv_read_public_command(0x01C00002).hex()
        '80010000000e0000016901c00002'
    """
    return _command(_ST_NO_SESSIONS, _CC_NV_READ_PUBLIC, struct.pack(">I", index))


def parse_nv_read_public(response: bytes) -> NvPublic:
    """Return the public area a ``TPM2_NV_ReadPublic`` response carries.

    Raises:
        TpmResponseError: the TPM refused (the index is not defined: ``0x18b``).
        ValueError: the response is malformed.
    """
    body = _response_body(response)
    _size, index, name_alg, attributes, policy_size = _unpack(">HIHIH", body)
    (data_size,) = _unpack(">H", body, 2 + 4 + 2 + 4 + 2 + policy_size)
    return NvPublic(index=index, name_alg=name_alg, attributes=attributes, data_size=data_size)


def nv_read_auth(public: NvPublic) -> int:
    """Return the handle a read of this index authorizes as.

    Raises:
        SourceError: neither the index nor the owner may read it with a password.
    """
    if public.attributes & _AUTHREAD:
        return public.index
    if public.attributes & _OWNERREAD:
        return _RH_OWNER
    msg = f"TPM nv index 0x{public.index:08x}: neither AUTHREAD nor OWNERREAD"
    raise SourceError(msg)


def nv_read_command(*, auth: int, index: int, size: int, offset: int) -> bytes:
    """Return ``TPM2_NV_Read`` of ``size`` bytes at ``offset``, authorized as ``auth``.

    Example:
        >>> nv_read_command(auth=0x01C00002, index=0x01C00002, size=512, offset=0).hex()[:28]
        '8002000000230000014e01c00002'
    """
    handles = struct.pack(">II", auth, index)
    auth_area = struct.pack(">I", len(_PASSWORD_SESSION)) + _PASSWORD_SESSION
    return _command(_ST_SESSIONS, _CC_NV_READ, handles + auth_area + struct.pack(">HH", size, offset))


def parse_nv_read(response: bytes) -> bytes:
    """Return the data a ``TPM2_NV_Read`` response carries.

    Raises:
        TpmResponseError: the TPM refused.
        ValueError: the response is malformed.
    """
    body = _response_body(response)
    _parameter_size, length = _unpack(">IH", body)
    data = body[6 : 6 + length]
    if len(data) != length:
        msg = f"TPM2_NV_Read states {length} bytes, holds {len(data)}"
        raise ValueError(msg)
    return data


__all__ = [
    "NV_CHUNK",
    "NvPublic",
    "TpmResponseError",
    "nv_read_auth",
    "nv_read_command",
    "nv_read_public_command",
    "parse_nv_read",
    "parse_nv_read_public",
]
