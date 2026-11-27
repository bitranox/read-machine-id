"""The Linux machine's files, read directly (never through a tool's printed output).

:class:`FilesystemReader` reads absolute machine paths under a root directory: ``/`` for the real
machine, a directory that mirrors ``/`` for a recorded one. Every failure is typed: a permission
refusal is :class:`NeedsRootError` (the value exists, an unprivileged run cannot see it), a path
that does not exist is :class:`MissingPathError`, anything else is :class:`SourceError` with the
errno name.

Contents:
    * :class:`FilesystemReader` - files, directories and links under a root.
    * :class:`SysfsLinuxSource` - the real machine's :class:`LinuxSource`.
"""

from __future__ import annotations

import errno
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

from ...application.machine_ports import DEFAULT_MAX_BYTES
from ...domain.machine_errors import SourceError
from .ethtool import ethtool_ioctl
from .netlink import netlink_dump
from .oserror import typed_os_error
from .tpm import TPM_DEVICE, device_transport, read_nv_index

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from ...application.machine_ports import NetlinkDump

_T = TypeVar("_T")


class FilesystemReader:
    """Files, directories and links of a machine, read under ``root``."""

    def __init__(self, root: Path) -> None:
        """Read the machine's ``/`` at ``root``."""
        self._root = root

    def _local(self, path: str) -> Path:
        if not path.startswith("/"):
            raise SourceError(f"{path}: not an absolute path")
        return self._root.joinpath(*path.strip("/").split("/"))

    def _call(self, path: str, action: Callable[[Path], _T]) -> _T:
        try:
            return action(self._local(path))
        except OSError as exc:
            raise typed_os_error(path, exc) from exc

    def read_bytes(self, path: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
        """Return a file's content; refuse one larger than ``max_bytes`` without reading it whole."""

        def read(local: Path) -> bytes:
            with local.open("rb") as handle:
                return handle.read(max_bytes + 1)

        data = self._call(path, read)
        if len(data) > max_bytes:
            raise SourceError(f"{path}: more than {max_bytes} bytes")
        return data

    def read_text(self, path: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
        """Return a text file's content, UTF-8 decoded with undecodable bytes replaced."""
        return self.read_bytes(path, max_bytes=max_bytes).decode("utf-8", errors="replace")

    def read_prefix(self, path: str, *, size: int) -> bytes:
        """Return at most the first ``size`` bytes of a file or device (a LUKS header on a disk)."""

        def read(local: Path) -> bytes:
            with local.open("rb") as handle:
                return handle.read(size)

        return self._call(path, read)

    def list_dir(self, path: str) -> list[str]:
        """Return the names in a directory, sorted."""
        return self._call(path, lambda local: sorted(entry.name for entry in local.iterdir()))

    def readlink(self, path: str) -> str:
        """Return a symbolic link's target as written in the link."""
        local = self._local(path)
        try:
            return str(local.readlink())
        except OSError as exc:
            if exc.errno == errno.EINVAL:  # the path exists and is not a link
                raise SourceError(f"{path}: not a link") from exc
            raise typed_os_error(path, exc) from exc


class SysfsLinuxSource(FilesystemReader):
    """The real machine: files under ``/``, the ethtool ioctl, rtnetlink and the TPM."""

    def __init__(self, root: Path | None = None) -> None:
        """Read the machine this runs on (``root`` exists for tests)."""
        super().__init__(root if root is not None else Path("/"))

    def ethtool(self, ifname: str, *, request: bytes) -> bytes:
        """Run one ethtool request on ``ifname`` (see :func:`ethtool_ioctl`)."""
        return ethtool_ioctl(ifname, request)

    def netlink_dump(self, table: NetlinkDump) -> Iterator[bytes]:
        """Yield every message of one rtnetlink dump (see :func:`netlink_dump`)."""
        return netlink_dump(table)

    def tpm_nv_read(self, index: int) -> bytes:
        """Return the content of a TPM NV index, read through the resource manager device."""
        with device_transport(self._local(TPM_DEVICE)) as transmit:
            return read_nv_index(transmit, index)


__all__ = ["FilesystemReader", "SysfsLinuxSource"]
