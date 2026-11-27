"""The ``SIOCETHTOOL`` ioctl: one ethtool question to one network interface.

The request is the whole ethtool structure (built by :mod:`fingerprint_machine.domain.ethtool`);
the kernel fills it in place through a pointer in a ``struct ifreq``, and the filled structure is
the answer. Most questions are open to every user; a few (wake-on-LAN) need ``CAP_NET_ADMIN``,
and the kernel then answers EPERM, reported as :class:`NeedsRootError`.

Contents:
    * :func:`ethtool_ioctl` - ask one question.
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys

from ...domain.machine_errors import SourceError
from .oserror import typed_os_error

if sys.platform != "win32":
    # POSIX only; this package is also imported (and type-checked) on Windows.
    import fcntl

_SIOCETHTOOL = 0x8946
_IFNAMSIZ = 16
# struct ifreq: the interface name, then a union whose ifr_data member is the request pointer.
_IFREQ = struct.Struct(f"{_IFNAMSIZ}sP")
_IFREQ_SIZE = 40


def ethtool_ioctl(ifname: str, request: bytes) -> bytes:
    """Run one ethtool request on ``ifname`` and return the structure the kernel filled.

    Raises:
        NeedsRootError: the question needs ``CAP_NET_ADMIN``.
        SourceError: the interface name is too long, the interface is gone, or the driver does
            not answer this question.
    """
    name = ifname.encode()
    if len(name) >= _IFNAMSIZ:
        raise SourceError(f"ethtool {ifname}: interface name longer than {_IFNAMSIZ - 1} bytes")
    if sys.platform == "win32":
        raise SourceError(f"ethtool {ifname}: needs Linux, this is {sys.platform}")
    buffer = ctypes.create_string_buffer(request, len(request))
    ifreq = bytearray(_IFREQ.pack(name, ctypes.addressof(buffer)).ljust(_IFREQ_SIZE, b"\0"))
    command = int.from_bytes(request[:4], "little")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            fcntl.ioctl(sock.fileno(), _SIOCETHTOOL, ifreq)
        except OSError as exc:
            raise typed_os_error(f"ethtool {ifname} 0x{command:02x}", exc) from exc
    return buffer.raw


__all__ = ["ethtool_ioctl"]
