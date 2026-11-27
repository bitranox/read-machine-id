"""Load, save, compare and check readings.

Contents:
    * :func:`load_reading` - a reading from a JSON file.
    * :func:`save_json` - write any JSON document to a file, atomically.
    * :func:`compare_files` - compare two saved readings.
    * :func:`check` - compare a saved baseline with a fresh reading of this machine.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..domain.compare import Comparison, compare_readings, comparison_document
from ..domain.machine_errors import NotAReadingError

if TYPE_CHECKING:
    from ..domain.json_types import JsonObject, JsonValue


def _label(reading: JsonObject, fallback: str) -> str:
    meta = reading.get("meta")
    label = meta.get("label") if isinstance(meta, dict) else None
    return label if isinstance(label, str) and label else fallback


def load_reading(path: Path) -> JsonObject:
    """Return the reading saved in ``path``.

    A ``collect --json`` envelope is accepted too: its ``data`` is the reading.

    Raises:
        NotAReadingError: the file cannot be read, is not JSON, or holds no ``meta`` object.
    """
    try:
        document: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NotAReadingError(f"{path}: {exc}") from exc
    if isinstance(document, dict):
        envelope = cast("dict[str, object]", document)
        if "meta" not in envelope and isinstance(envelope.get("data"), dict):
            document = envelope["data"]
    if not isinstance(document, dict) or not isinstance(cast("dict[str, object]", document).get("meta"), dict):
        raise NotAReadingError(f"{path}: not a reading (no 'meta' object)")
    return cast("JsonObject", document)


def save_json(path: Path, document: JsonValue) -> None:
    """Write ``document`` to ``path`` as indented UTF-8 JSON, replacing it in one step.

    The text goes to a temporary file beside ``path`` first, so a crash or a full disk never
    leaves a half-written reading where a good one stood.

    Raises:
        OSError: the directory is not writable or the disk is full.
    """
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    target = path.resolve()
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def compare_files(original: Path, actual: Path) -> tuple[Comparison, JsonObject]:
    """Compare two saved readings; return the comparison and its JSON document."""
    a, b = load_reading(original), load_reading(actual)
    cmp = compare_readings(a, b)
    return cmp, comparison_document(cmp, (_label(a, original.name), _label(b, actual.name)))


def check(baseline: JsonObject, fresh: JsonObject) -> tuple[Comparison, JsonObject]:
    """Compare a baseline reading with a fresh one; return the comparison and its document."""
    cmp = compare_readings(baseline, fresh)
    return cmp, comparison_document(cmp, (_label(baseline, "baseline"), _label(fresh, "this machine")))


__all__ = ["check", "compare_files", "load_reading", "save_json"]
