"""One guarded question: an answer, or the reason there is none, recorded in its place.

Contents:
    * :data:`ANSWER_ERRORS` - what a source may raise instead of answering.
    * :func:`guarded` - ask one question, record a refusal as ``{"error": ...}``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.machine_errors import SourceError

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..domain.json_types import JsonValue

#: What a guarded question may raise besides SourceError: a missing row, value or key, or a value
#: of the wrong shape. Anything else is a defect in this tool and surfaces.
ANSWER_ERRORS: tuple[type[Exception], ...] = (SourceError, KeyError, IndexError, ValueError, TypeError)


def guarded(read: Callable[[], JsonValue]) -> JsonValue:
    """Return ``read()``, or ``{"error": "<type>: <message>"}`` when the source refused.

    Examples:
        >>> guarded(lambda: 1)
        1
        >>> guarded(lambda: {}["missing"])
        {'error': "KeyError: 'missing'"}
    """
    try:
        return read()
    except ANSWER_ERRORS as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


__all__ = ["ANSWER_ERRORS", "guarded"]
