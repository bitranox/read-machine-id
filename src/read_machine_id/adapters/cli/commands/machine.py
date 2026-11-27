"""The machine commands: ``collect``, ``compare`` and ``check``.

Contents:
    * :data:`cli_collect` - read this machine.
    * :data:`cli_compare` - compare two saved readings (any OS).
    * :data:`cli_check` - compare a saved baseline with this machine.

Exit codes (see :class:`~..machine_output.MachineExit`): 0 done, 1 ``check`` or ``compare``
found differences, 2 refused (not Windows, a file that is not a reading, an unwritable output).
"""

from __future__ import annotations

import datetime as dt
import platform
from pathlib import Path
from typing import TYPE_CHECKING

import rich_click as click

from read_machine_id import __init__conf__

from ....application.collect import Section, collect
from ....application.readings import check, compare_files, load_reading, save_json
from ....domain.machine_errors import NotAReadingError, UnsupportedPlatformError
from ..constants import CLICK_CONTEXT_SETTINGS
from ..context import get_cli_context
from ..machine_output import (
    MachineExit,
    OutputMode,
    emit_failure,
    emit_success,
    render_comparison,
    render_reading,
    skipped_answers,
)
from ..typed_click import argument, option

if TYPE_CHECKING:
    from collections.abc import Callable

    from ....domain.compare import Comparison
    from ....domain.json_types import JsonObject

#: The failures a machine command reports as a refusal (exit 2) instead of a crash.
_REFUSALS: tuple[type[Exception], ...] = (NotAReadingError, UnsupportedPlatformError, OSError)

_SECTION_NAMES = [s.value for s in Section]


def _mode(as_json: bool, bare: bool) -> OutputMode:
    if bare:
        return OutputMode.JSON_BARE
    return OutputMode.JSON if as_json else OutputMode.HUMAN


def _json_options(func: Callable[..., None]) -> Callable[..., None]:
    func = option("--json-bare", "bare", is_flag=True, help="Print only the data as JSON, and JSON on failure too.")(
        func
    )
    return option("--json", "as_json", is_flag=True, help="Print the JSON envelope {ok, command, data, skipped}.")(func)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _read_machine(ctx: click.Context, label: str | None, sections: tuple[str, ...]) -> JsonObject:
    sources = get_cli_context(ctx).services.machine_sources()
    return collect(
        sources,
        label=label or platform.node() or "this machine",
        collected_at=_now(),
        tool_version=__init__conf__.version,
        sections=[Section(s) for s in sections] or None,
    )


def _finish_comparison(
    ctx: click.Context,
    mode: OutputMode,
    command: str,
    result: tuple[Comparison, JsonObject],
    *,
    diff_only: bool,
    out: Path | None,
) -> None:
    cmp, document = result
    if out is not None:
        save_json(out, document)
    emit_success(mode, command, document, skipped=[], human=render_comparison(cmp, document, diff_only=diff_only))
    ctx.exit(int(MachineExit.DIFFERENT if cmp.differences() else MachineExit.DONE))


_OUT = click.Path(dir_okay=False, writable=True, readable=False, path_type=Path)
_IN = click.Path(exists=False, dir_okay=False, path_type=Path)


@click.command("collect", context_settings=CLICK_CONTEXT_SETTINGS)
@option(
    "--section",
    "sections",
    multiple=True,
    type=click.Choice(_SECTION_NAMES),
    help="Read only this section (repeatable).",
)
@option("--label", default=None, help="A name for this reading (default: the computer name).")
@option("--out", type=_OUT, default=None, help="Also save the reading to this file.")
@_json_options
@click.pass_context
def cli_collect(
    ctx: click.Context, *, sections: tuple[str, ...], label: str | None, out: Path | None, as_json: bool, bare: bool
) -> None:
    """Read everything this Windows machine says about itself.

    SMBIOS, ACPI, firmware, CPU, memory, disks, every network adapter with its PCI location and
    settings, every device, Windows ids and licensing, TPM and security state. Product keys are
    masked to their last five characters.

    \f
    Example:
        >>> import json
        >>> from click.testing import CliRunner
        >>> from read_machine_id.adapters.cli.root import cli
        >>> from read_machine_id.composition import build_testing
        >>> result = CliRunner().invoke(cli, ["collect", "--section", "cpu", "--json"], obj=build_testing)
        >>> result.exit_code, json.loads(result.stdout)["data"]["meta"]["sections"]
        (0, ['cpu'])
    """
    mode = _mode(as_json, bare)
    try:
        reading = _read_machine(ctx, label, sections)
        if out is not None:
            save_json(out, reading)
    except _REFUSALS as exc:
        emit_failure(mode, "collect", exc)
        ctx.exit(int(MachineExit.ERROR))
    emit_success(mode, "collect", reading, skipped=skipped_answers(reading), human=render_reading(reading))


@click.command("compare", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("original", type=_IN)
@argument("actual", type=_IN)
@option("--diff-only", is_flag=True, help="Show only the fields that differ.")
@option("--out", type=_OUT, default=None, help="Also save the comparison to this file.")
@_json_options
@click.pass_context
def cli_compare(
    ctx: click.Context, *, original: Path, actual: Path, diff_only: bool, out: Path | None, as_json: bool, bare: bool
) -> None:
    """Compare two saved readings field by field. Exit 1 when they differ.

    \f
    Example:
        >>> import json, shutil, tempfile
        >>> from pathlib import Path
        >>> from click.testing import CliRunner
        >>> from read_machine_id.adapters.cli.root import cli
        >>> from read_machine_id.composition import build_testing
        >>> folder = Path(tempfile.mkdtemp())
        >>> saved = str(folder / "a.json")
        >>> CliRunner().invoke(cli, ["collect", "--out", saved], obj=build_testing).exit_code
        0
        >>> result = CliRunner().invoke(cli, ["compare", saved, saved, "--json-bare"], obj=build_testing)
        >>> result.exit_code, json.loads(result.stdout)["differences"]
        (0, [])
        >>> shutil.rmtree(folder)
    """
    mode = _mode(as_json, bare)
    try:
        result = compare_files(original, actual)
        _finish_comparison(ctx, mode, "compare", result, diff_only=diff_only, out=out)
    except _REFUSALS as exc:
        emit_failure(mode, "compare", exc)
        ctx.exit(int(MachineExit.ERROR))


@click.command("check", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("baseline", type=_IN)
@option("--diff-only", is_flag=True, help="Show only the fields that differ.")
@option("--save", type=_OUT, default=None, help="Also save this machine's fresh reading to this file.")
@option("--out", type=_OUT, default=None, help="Also save the comparison to this file.")
@_json_options
@click.pass_context
def cli_check(
    ctx: click.Context,
    *,
    baseline: Path,
    diff_only: bool,
    save: Path | None,
    out: Path | None,
    as_json: bool,
    bare: bool,
) -> None:
    """Read this machine and compare it with a saved baseline. Exit 1 when it differs.

    \f
    Example:
        >>> import json, shutil, tempfile
        >>> from pathlib import Path
        >>> from click.testing import CliRunner
        >>> from read_machine_id.adapters.cli.root import cli
        >>> from read_machine_id.composition import build_testing
        >>> folder = Path(tempfile.mkdtemp())
        >>> baseline = str(folder / "base.json")
        >>> CliRunner().invoke(cli, ["collect", "--out", baseline], obj=build_testing).exit_code
        0
        >>> result = CliRunner().invoke(cli, ["check", baseline, "--json"], obj=build_testing)
        >>> result.exit_code, json.loads(result.stdout)["data"]["differences"]
        (0, [])
        >>> shutil.rmtree(folder)
    """
    mode = _mode(as_json, bare)
    try:
        base = load_reading(baseline)
        fresh = _read_machine(ctx, None, ())
        if save is not None:
            save_json(save, fresh)
        _finish_comparison(ctx, mode, "check", check(base, fresh), diff_only=diff_only, out=out)
    except _REFUSALS as exc:
        emit_failure(mode, "check", exc)
        ctx.exit(int(MachineExit.ERROR))


__all__ = ["cli_check", "cli_collect", "cli_compare"]
