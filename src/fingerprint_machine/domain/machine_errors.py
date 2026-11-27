"""The errors of reading and comparing machines.

Contents:
    * :class:`SourceError` - a source could not answer one question; the reading goes on.
    * :class:`MissingKeyError` - the registry key asked for does not exist.
    * :class:`MissingPathError` - the file or directory asked for does not exist (Linux).
    * :class:`NeedsRootError` - only root may read what was asked for (Linux).
    * :class:`UnsupportedPlatformError` - this machine cannot be read (neither Windows nor Linux).
    * :class:`NotAReadingError` - a file given as a reading is not one.
"""

from __future__ import annotations


class SourceError(Exception):
    """A source could not answer one question: a class, key or table it cannot read.

    Example:
        >>> str(SourceError("Win32_Tpm: access denied"))
        'Win32_Tpm: access denied'
    """


class MissingKeyError(SourceError):
    """The registry key asked for does not exist.

    For an optional key (cloud join, cached EK certificates) that is the answer itself: the
    machine is not joined, nothing is cached. Readers of such keys catch this one and report an
    empty result; every other reader lets it through as an unanswered question.

    Example:
        >>> isinstance(MissingKeyError(r"HKLM\\SOFTWARE\\X: key not found"), SourceError)
        True
    """


class MissingPathError(SourceError):
    """The file or directory asked for does not exist.

    Like :class:`MissingKeyError`: for an optional path (a device class this machine has none
    of) that is the answer itself, and readers of such paths report an empty result.

    Example:
        >>> isinstance(MissingPathError("/sys/class/tpm: no such file or directory"), SourceError)
        True
    """


class NeedsRootError(SourceError):
    """Only root may read what was asked for: a serial number, a firmware table, a device.

    Recorded per value as ``{"error": "NeedsRootError: ..."}``, never as absent: the value exists,
    an unprivileged run just cannot see it.

    Example:
        >>> str(NeedsRootError("/sys/firmware/dmi/tables/DMI: needs root"))
        '/sys/firmware/dmi/tables/DMI: needs root'
    """


class UnsupportedPlatformError(Exception):
    """The machine this runs on cannot be read: collecting needs Windows or Linux.

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


__all__ = [
    "MissingKeyError",
    "MissingPathError",
    "NeedsRootError",
    "NotAReadingError",
    "SourceError",
    "UnsupportedPlatformError",
]
