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
from ...domain.machine_errors import MissingPathError, NeedsRootError, SourceError
from .tpm import TPM_DEVICE, device_transport, read_nv_index

if TYPE_CHECKING:
    from collections.abc import Callable

    from ...application.machine_ports import NetlinkDump

_T = TypeVar("_T")
_ROOT_ONLY = frozenset({errno.EACCES, errno.EPERM})
_MISSING = frozenset({errno.ENOENT, errno.ENOTDIR})


def _typed(path: str, exc: OSError) -> SourceError:
    """The error a refused filesystem call is reported as."""
    code = exc.errno or 0
    name = errno.errorcode.get(code, str(code))
    if code in _ROOT_ONLY:
        return NeedsRootError(f"{path}: needs root ({name})")
    if code in _MISSING:
        return MissingPathError(f"{path}: does not exist ({name})")
    return SourceError(f"{path}: {name} {exc.strerror or ''}".rstrip())


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
            raise _typed(path, exc) from exc

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
            raise _typed(path, exc) from exc


def _not_yet(what: str) -> SourceError:
    return SourceError(f"{what}: not implemented yet")


class SysfsLinuxSource(FilesystemReader):
    """The real machine's files under ``/`` and its TPM; ethtool and netlink come in a later version."""

    def __init__(self, root: Path | None = None) -> None:
        """Read the machine this runs on (``root`` exists for tests)."""
        super().__init__(root if root is not None else Path("/"))

    def ethtool(self, ifname: str, *, request: bytes) -> bytes:
        """Refuse: the ethtool ioctl is not wired yet."""
        del request
        raise _not_yet(f"ethtool {ifname}")

    def netlink_dump(self, table: NetlinkDump) -> list[bytes]:
        """Refuse: the netlink dump is not wired yet."""
        raise _not_yet(f"netlink {table.value}")

    def tpm_nv_read(self, index: int) -> bytes:
        """Return the content of a TPM NV index, read through the resource manager device."""
        with device_transport(self._local(TPM_DEVICE)) as transmit:
            return read_nv_index(transmit, index)


__all__ = ["FilesystemReader", "SysfsLinuxSource"]
