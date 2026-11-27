"""Reading a TPM NV index: the command bytes, the piecewise read, and every refusal.

The TPM is a small simulator that answers the two commands from a table of NV indices, built from
the command layout in TPM 2.0 Part 3 (31.6, 31.13); it is the transport the real device would be.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from fingerprint_machine.adapters.linux.sysfs import SysfsLinuxSource
from fingerprint_machine.adapters.linux.tpm import device_transport, read_nv_index
from fingerprint_machine.domain.machine_errors import MissingPathError, SourceError
from fingerprint_machine.domain.tpm2 import TpmResponseError

if TYPE_CHECKING:
    from pathlib import Path

_AUTHREAD = 1 << 18
_OWNERREAD = 1 << 17
_OWNER = 0x40000001
_EK_RSA = 0x01C00002


def _response(tag: int, code: int, body: bytes = b"") -> bytes:
    return struct.pack(">HII", tag, 10 + len(body), code) + body


@dataclass
class _Tpm:
    """Answers NV_ReadPublic and NV_Read from ``indices``; records every read's auth, size, offset."""

    indices: dict[int, tuple[int, bytes]]
    reads: list[tuple[int, int, int]] = field(default_factory=list[tuple[int, int, int]])

    def __call__(self, command: bytes) -> bytes:
        _tag, _size, code = struct.unpack_from(">HII", command)
        index = struct.unpack_from(">I", command, 10 if code == 0x169 else 14)[0]
        if index not in self.indices:
            return _response(0x8001, 0x18B)
        attributes, data = self.indices[index]
        if code == 0x169:
            public = struct.pack(">IHIH", index, 0x000B, attributes, 0) + struct.pack(">H", len(data))
            return _response(0x8001, 0, struct.pack(">H", len(public)) + public + struct.pack(">H", 0))
        auth = struct.unpack_from(">I", command, 10)[0]
        size, offset = struct.unpack_from(">HH", command, len(command) - 4)
        self.reads.append((auth, size, offset))
        piece = data[offset : offset + size]
        return _response(0x8002, 0, struct.pack(">IH", 2 + len(piece), len(piece)) + piece)


@pytest.mark.os_agnostic
def test_an_index_is_read_in_pieces_authorized_as_itself() -> None:
    content = bytes(range(256)) * 5
    tpm = _Tpm({_EK_RSA: (_AUTHREAD, content)})
    assert read_nv_index(tpm, _EK_RSA) == content
    assert tpm.reads == [(_EK_RSA, 512, 0), (_EK_RSA, 512, 512), (_EK_RSA, 256, 1024)]


@pytest.mark.os_agnostic
def test_an_owner_readable_index_is_read_as_the_owner() -> None:
    tpm = _Tpm({_EK_RSA: (_OWNERREAD, b"cert")})
    assert read_nv_index(tpm, _EK_RSA) == b"cert"
    assert tpm.reads == [(_OWNER, 4, 0)]


@pytest.mark.os_agnostic
def test_an_undefined_index_is_the_tpm_s_handle_error() -> None:
    with pytest.raises(TpmResponseError) as caught:
        read_nv_index(_Tpm({}), _EK_RSA)
    assert caught.value.index_undefined


@pytest.mark.os_agnostic
def test_an_index_no_password_may_read_is_refused() -> None:
    with pytest.raises(SourceError, match="neither AUTHREAD nor OWNERREAD"):
        read_nv_index(_Tpm({_EK_RSA: (0, b"cert")}), _EK_RSA)


@pytest.mark.os_agnostic
def test_a_short_response_is_a_malformed_answer() -> None:
    with pytest.raises(ValueError, match="too short"):
        read_nv_index(lambda _command: _response(0x8001, 0, b"\x00"), _EK_RSA)


@pytest.mark.os_agnostic
def test_a_machine_without_the_device_has_no_tpm(tmp_path: Path) -> None:
    with pytest.raises(MissingPathError, match="/dev/tpmrm0"):
        SysfsLinuxSource(root=tmp_path).tpm_nv_read(_EK_RSA)


@pytest.mark.os_posix
def test_the_device_transport_writes_one_command_and_reads_one_response(tmp_path: Path) -> None:
    device = tmp_path / "tpmrm0"
    device.write_bytes(b"")
    with device_transport(device) as transmit:
        # A regular file: the write lands at the start, the read finds the end of file.
        assert transmit(b"\x80\x01") == b""
    assert device.read_bytes() == b"\x80\x01"
