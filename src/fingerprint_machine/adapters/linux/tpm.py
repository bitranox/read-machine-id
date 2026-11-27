"""Read a TPM 2.0 non-volatile index through the kernel's resource manager, ``/dev/tpmrm0``.

The device takes one whole command per ``write`` and hands back one whole response per ``read``;
the resource manager lets several processes share the TPM, so nothing here needs a lock. The
command bytes come from :mod:`fingerprint_machine.domain.tpm2`; this module only moves them.

Contents:
    * :data:`TPM_DEVICE` - the device path.
    * :func:`read_nv_index` - the whole content of an index, over any transport.
    * :func:`device_transport` - a transport over the device.
"""

from __future__ import annotations

import contextlib
import errno
import os
from typing import TYPE_CHECKING

from ...domain.machine_errors import MissingPathError, NeedsRootError, SourceError
from ...domain.tpm2 import (
    NV_CHUNK,
    nv_read_auth,
    nv_read_command,
    nv_read_public_command,
    parse_nv_read,
    parse_nv_read_public,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

#: The kernel's TPM resource manager device.
TPM_DEVICE = "/dev/tpmrm0"
# TPM 2.0 caps a response at TPM_MAX_COMMAND_SIZE, 4096 bytes on every TPM in use.
_MAX_RESPONSE = 4096

#: One command in, its response out.
type Transport = Callable[[bytes], bytes]


def read_nv_index(transmit: Transport, index: int) -> bytes:
    """Return the whole content of NV ``index``: its public area first, then the data piece by piece.

    Raises:
        TpmResponseError: the TPM refused a command (``0x18b``: the index is not defined).
        SourceError: the index may not be read with an empty password.
    """
    public = parse_nv_read_public(transmit(nv_read_public_command(index)))
    auth = nv_read_auth(public)
    content = bytearray()
    while len(content) < public.data_size:
        size = min(NV_CHUNK, public.data_size - len(content))
        content += parse_nv_read(transmit(nv_read_command(auth=auth, index=index, size=size, offset=len(content))))
    return bytes(content)


def _open_error(path: str, exc: OSError) -> SourceError:
    if exc.errno in {errno.EACCES, errno.EPERM}:
        return NeedsRootError(f"{path}: needs root")
    if exc.errno in {errno.ENOENT, errno.ENODEV, errno.ENXIO}:
        return MissingPathError(f"{path}: no TPM resource manager")
    return SourceError(f"{path}: {exc.strerror or exc}")


@contextlib.contextmanager
def device_transport(local: Path, *, shown_as: str = TPM_DEVICE) -> Generator[Transport]:
    """Open the TPM device at ``local`` and yield a transport over it; close it afterwards.

    Raises:
        NeedsRootError: the device may not be opened (it is ``root:tss 0660``).
        MissingPathError: there is no device.
        SourceError: a write or read failed.
    """
    try:
        fd = os.open(local, os.O_RDWR)
    except OSError as exc:
        raise _open_error(shown_as, exc) from exc

    def transmit(command: bytes) -> bytes:
        try:
            os.write(fd, command)
            return os.read(fd, _MAX_RESPONSE)
        except OSError as exc:
            raise SourceError(f"{shown_as}: {exc.strerror or exc}") from exc

    try:
        yield transmit
    finally:
        os.close(fd)


__all__ = ["TPM_DEVICE", "Transport", "device_transport", "read_nv_index"]
