"""Load, save, compare and check readings.

Contents:
    * :data:`MAX_READING_BYTES`, :func:`load_reading` - a reading from a JSON file, and its cap.
    * :func:`save_json` - write any JSON document to a file, atomically.
    * :class:`ComparisonResult` - a comparison and the JSON document that reports it.
    * :func:`compare_files` - compare two saved readings.
    * :func:`check` - compare a saved baseline with a fresh reading of this machine.
"""

from __future__ import annotations

import json
import os
import secrets
from typing import TYPE_CHECKING, NamedTuple, cast

from ..domain.compare import Comparison, compare_readings, comparison_document
from ..domain.machine_errors import NotAReadingError

if TYPE_CHECKING:
    from pathlib import Path

    from ..domain.json_types import JsonObject, JsonValue


#: The largest file read as a reading. A real reading is a few MB; the cap keeps a wrong path
#: (a device, ``/dev/zero``, a disk image) from being read until memory runs out.
MAX_READING_BYTES = 256 * 1024 * 1024
_CHUNK = 1024 * 1024


def _read_capped(path: Path, max_bytes: int) -> bytes:
    """Return a file's content, refusing it as soon as it passes ``max_bytes``."""
    chunks: list[bytes] = []
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(min(_CHUNK, max_bytes + 1 - total)):
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"more than {max_bytes} bytes, too large for a reading")
            chunks.append(chunk)
    return b"".join(chunks)


def _label(reading: JsonObject, fallback: str) -> str:
    meta = reading.get("meta")
    label = meta.get("label") if isinstance(meta, dict) else None
    return label if isinstance(label, str) and label else fallback


def load_reading(path: Path, *, max_bytes: int = MAX_READING_BYTES) -> JsonObject:
    """Return the reading saved in ``path``.

    A ``collect --json`` envelope is accepted too: its ``data`` is the reading.

    Args:
        path: the file to read.
        max_bytes: the largest file accepted; a larger one is refused without being read whole.

    Raises:
        NotAReadingError: the file cannot be read, is larger than ``max_bytes``, is not UTF-8
            JSON, or holds no ``meta`` object.
    """
    try:
        document: object = json.loads(_read_capped(path, max_bytes).decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise NotAReadingError(f"{path}: {exc}") from exc
    if isinstance(document, dict):
        envelope = cast("dict[str, object]", document)
        if "meta" not in envelope and isinstance(envelope.get("data"), dict):
            document = envelope["data"]
    if not isinstance(document, dict) or not isinstance(cast("dict[str, object]", document).get("meta"), dict):
        raise NotAReadingError(f"{path}: not a reading (no 'meta' object)")
    return cast("JsonObject", document)


# O_BINARY (Windows only) keeps the C runtime from turning each \n into \r\n, as tempfile does.
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
# The mode a plain open(path, "w") asks for; the kernel takes the umask off it.
_NEW_FILE_MODE = 0o666
_TEMP_NAME_ATTEMPTS = 8


def _create_temp_beside(target: Path) -> tuple[int, Path]:
    """Create a new, empty temporary file beside ``target``, with the mode a plain write gives.

    tempfile.mkstemp always creates its file 0600 whatever the umask, so a reading saved through
    it, taken under sudo, could not be read by the user who asked for it.
    """
    for _ in range(_TEMP_NAME_ATTEMPTS):
        tmp = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
        try:
            return os.open(tmp, _NEW_FILE_FLAGS, _NEW_FILE_MODE), tmp
        except FileExistsError:
            continue
    raise FileExistsError(f"no free temporary name beside {target}")


def save_json(path: Path, document: JsonValue) -> None:
    """Write ``document`` to ``path`` as indented UTF-8 JSON, replacing it in one step.

    The text goes to a temporary file beside ``path`` first, so a crash or a full disk never
    leaves a half-written reading where a good one stood. The file gets the mode a plain write
    would give it: 0666 less the umask.

    Raises:
        OSError: the directory is not writable or the disk is full.
    """
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    target = path.resolve()
    fd, tmp = _create_temp_beside(target)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        tmp.replace(target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


class ComparisonResult(NamedTuple):
    """A comparison of two readings and the JSON document that reports it."""

    comparison: Comparison
    document: JsonObject


def compare_files(original: Path, actual: Path) -> ComparisonResult:
    """Compare two saved readings; return the comparison and its JSON document."""
    a, b = load_reading(original), load_reading(actual)
    cmp = compare_readings(a, b)
    return ComparisonResult(cmp, comparison_document(cmp, (_label(a, original.name), _label(b, actual.name))))


def check(baseline: JsonObject, fresh: JsonObject) -> ComparisonResult:
    """Compare a baseline reading with a fresh one; return the comparison and its document."""
    cmp = compare_readings(baseline, fresh)
    labels = (_label(baseline, "baseline"), _label(fresh, "this machine"))
    return ComparisonResult(cmp, comparison_document(cmp, labels))


__all__ = ["MAX_READING_BYTES", "ComparisonResult", "check", "compare_files", "load_reading", "save_json"]
