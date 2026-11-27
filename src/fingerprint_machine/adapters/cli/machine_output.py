"""How the machine commands print: the JSON envelope, and readable tables for people.

Machine output follows one contract for every command:

* ``--json`` prints ``{"ok": true, "command": ..., "data": ..., "skipped": [...]}`` on success
  and ``{"ok": false, "command": ..., "error": {"type": ..., "message": ...}}`` on failure.
* ``--json-bare`` prints only ``data`` on success, and the same failure object on failure, so a
  caller parsing standard output always gets JSON.
* Warnings and progress go to standard error, never into the parsed stream.

Contents:
    * :class:`MachineExit` - the exit codes.
    * :class:`OutputMode` - how a command prints.
    * :func:`skipped_answers` - every question a reading could not answer.
    * :func:`emit_success` / :func:`emit_failure` - print the result.
"""

from __future__ import annotations

import json
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

from ...domain.compare import DIFFERING, flatten
from . import safe_console

if TYPE_CHECKING:
    from ...domain.compare import Comparison
    from ...domain.json_types import JsonObject, JsonValue


class MachineExit(IntEnum):
    """Exit codes of the machine commands: they do not depend on the output mode."""

    DONE = 0
    DIFFERENT = 1
    ERROR = 2


class OutputMode(StrEnum):
    """How a command prints its result."""

    HUMAN = "human"
    JSON = "json"
    JSON_BARE = "json-bare"


def skipped_answers(reading: JsonValue) -> list[JsonValue]:
    """Return ``{"path", "error"}`` for every place a reading recorded an error instead of an answer.

    Examples:
        >>> skipped_answers({"security": {"tpm": {"error": "SourceError: denied"}, "tbs": {"x": 1}}})
        [{'path': 'security.tpm', 'error': 'SourceError: denied'}]
    """
    out: list[JsonValue] = []
    for path, value in flatten(reading):
        if path == "error" or path.endswith(".error"):
            out.append({"path": path.removesuffix(".error").removesuffix("error"), "error": value})
    return out


def _print_json(document: JsonValue) -> None:
    safe_console.echo(json.dumps(document, indent=2, ensure_ascii=False))


def emit_success(mode: OutputMode, command: str, data: JsonValue, *, skipped: list[JsonValue], human: str) -> None:
    """Print a successful result in ``mode``; ``human`` is the text for people."""
    if mode is OutputMode.JSON:
        _print_json({"ok": True, "command": command, "data": data, "skipped": skipped})
    elif mode is OutputMode.JSON_BARE:
        _print_json(data)
    else:
        safe_console.echo(human, nl=False)


def emit_failure(mode: OutputMode, command: str, exc: Exception) -> None:
    """Print a failure: a JSON object in the JSON modes, one ``Error:`` line on stderr otherwise."""
    if mode is OutputMode.HUMAN:
        safe_console.echo(f"Error: {exc}", err=True)
        return
    _print_json({"ok": False, "command": command, "error": {"type": type(exc).__name__, "message": str(exc)}})


def _render(table: Table) -> str:
    console = Console(record=True, width=160, file=safe_console.safe_stream())
    with console.capture() as capture:
        console.print(table)
    return capture.get()


def _short(value: JsonValue, limit: int = 70) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def render_reading(reading: JsonObject) -> str:
    """Return the summary of a reading as a two-column table, plus any skipped questions."""
    table = Table(title="Machine identity (summary)", show_lines=False)
    table.add_column("field")
    table.add_column("value")
    for path, value in flatten(reading.get("summary", {})):
        table.add_row(path, _short(value))
    text = _render(table)
    skipped = skipped_answers(reading)
    if skipped:
        text += f"{len(skipped)} question(s) could not be answered; --json lists them under 'skipped'.\n"
    return text


def render_comparison(cmp: Comparison, document: JsonObject, *, diff_only: bool) -> str:
    """Return the compared fields as a table (only the differing ones with ``diff_only``) and the score."""
    table = Table(title=f"{document['original']} -> {document['actual']}")
    for column in ("field", "original", "actual", "status"):
        table.add_column(column)
    for row in cmp.rows:
        if diff_only and row.status not in DIFFERING:
            continue
        table.add_row(row.path, _short(row.original, 40), _short(row.actual, 40), row.status.value)
    score = (
        f"identical: {document['identical']} of {document['scored']} scored fields ({document['identical_pct']} %)\n"
    )
    return _render(table) + score


__all__ = [
    "MachineExit",
    "OutputMode",
    "emit_failure",
    "emit_success",
    "render_comparison",
    "render_reading",
    "skipped_answers",
]
