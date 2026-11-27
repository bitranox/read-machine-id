"""CLI command implementations.

Collects all subcommand functions and re-exports them for registration
with the root CLI group.

Contents:
    * Info commands from :mod:`.info`
    * Config commands from :mod:`.config`
    * Logging commands from :mod:`.logging`
    * Machine commands from :mod:`.machine`
"""

from __future__ import annotations

from .config import cli_config, cli_config_deploy, cli_config_generate_examples
from .info import cli_fail, cli_info
from .logging import cli_logdemo
from .machine import cli_check, cli_collect, cli_compare

__all__ = [
    "cli_check",
    "cli_collect",
    "cli_compare",
    "cli_config",
    "cli_config_deploy",
    "cli_config_generate_examples",
    "cli_fail",
    "cli_info",
    "cli_logdemo",
]
