"""The errors of reading and comparing machines.

Contents:
    * :class:`SourceError` - a source could not answer one question; the reading goes on.
    * :class:`UnsupportedPlatformError` - this machine cannot be read (not Windows).
    * :class:`NotAReadingError` - a file given as a reading is not one.
"""

from __future__ import annotations


class SourceError(Exception):
    """A source could not answer one question: a class, key or table it cannot read.

    Example:
        >>> str(SourceError("Win32_Tpm: access denied"))
        'Win32_Tpm: access denied'
    """


class UnsupportedPlatformError(Exception):
    """The machine this runs on cannot be read: collecting needs Windows.

    Example:
        >>> isinstance(UnsupportedPlatformError("linux"), Exception)
        True
    """


class NotAReadingError(ValueError):
    """A file given as a reading cannot be read or does not hold one.

    Example:
        >>> isinstance(NotAReadingError("x.json: not JSON"), ValueError)
        True
    """


__all__ = ["NotAReadingError", "SourceError", "UnsupportedPlatformError"]
