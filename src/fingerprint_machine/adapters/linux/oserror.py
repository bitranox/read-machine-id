"""What a refused kernel call is reported as, the same for files, ioctls and sockets.

Contents:
    * :func:`typed_os_error` - the :class:`SourceError` an :class:`OSError` becomes.
"""

from __future__ import annotations

import errno

from ...domain.machine_errors import MissingPathError, NeedsRootError, SourceError

_ROOT_ONLY = frozenset({errno.EACCES, errno.EPERM})
_MISSING = frozenset({errno.ENOENT, errno.ENOTDIR})


def typed_os_error(what: str, exc: OSError) -> SourceError:
    """Return the error a refused call on ``what`` is reported as.

    A permission refusal is :class:`NeedsRootError` (the value exists, an unprivileged run cannot
    see it), a path that does not exist is :class:`MissingPathError`, anything else is
    :class:`SourceError` with the errno name.

    Example:
        >>> type(typed_os_error("/sys/x", PermissionError(errno.EACCES, "denied"))).__name__
        'NeedsRootError'
    """
    code = exc.errno or 0
    name = errno.errorcode.get(code, str(code))
    if code in _ROOT_ONLY:
        return NeedsRootError(f"{what}: needs root ({name})")
    if code in _MISSING:
        return MissingPathError(f"{what}: does not exist ({name})")
    return SourceError(f"{what}: {name} {exc.strerror or ''}".rstrip())


__all__ = ["typed_os_error"]
