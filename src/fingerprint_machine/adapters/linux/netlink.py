"""rtnetlink dumps over an ``AF_NETLINK`` socket: links, addresses, routes, neighbours.

One request asks for every entry; the kernel answers in batches until ``NLMSG_DONE``. Each
message is yielded as soon as its batch arrives, so one dump holds at most one batch in memory.
Reading these tables needs no privilege.

Contents:
    * :func:`netlink_dump` - yield every message of one dump.
"""

from __future__ import annotations

import errno
import socket
import sys
from typing import TYPE_CHECKING

from ...domain.machine_errors import SourceError
from ...domain.netlink import DumpKind, dump_request, error_number, is_done, split_messages
from .oserror import typed_os_error

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ...application.machine_ports import NetlinkDump

# One receive holds one kernel batch; batches are a few pages, this leaves room for large links.
_RECEIVE_BYTES = 256 * 1024
_TIMEOUT_SECONDS = 10.0


def _batches(sock: socket.socket, what: str) -> Iterator[bytes]:
    while True:
        try:
            buffer = sock.recv(_RECEIVE_BYTES)
        except OSError as exc:
            raise typed_os_error(what, exc) from exc
        if not buffer:
            raise SourceError(f"{what}: the kernel closed the socket before the dump ended")
        yield buffer


def netlink_dump(table: NetlinkDump) -> Iterator[bytes]:
    """Yield every message of one rtnetlink dump of ``table``, header included.

    Raises:
        NeedsRootError: the kernel refused the dump with EPERM or EACCES.
        SourceError: the socket cannot be opened, or the kernel answered another error.
    """
    what = f"netlink {table.value}"
    if sys.platform == "win32":
        raise SourceError(f"{what}: needs Linux, this is {sys.platform}")
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    except (OSError, AttributeError) as exc:  # AttributeError: a POSIX system without netlink
        raise SourceError(f"{what}: no netlink socket here ({exc})") from exc
    with sock:
        sock.settimeout(_TIMEOUT_SECONDS)
        try:
            sock.sendall(dump_request(DumpKind[table.name], sequence=1))
        except OSError as exc:
            raise typed_os_error(what, exc) from exc
        for buffer in _batches(sock, what):
            for message in split_messages(buffer):
                if is_done(message):
                    return
                code = error_number(message)
                if code is not None:
                    raise typed_os_error(what, OSError(code, errno.errorcode.get(code, str(code))))
                yield message


__all__ = ["netlink_dump"]
