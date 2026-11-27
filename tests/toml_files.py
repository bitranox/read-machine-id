"""Read a TOML file in the tests."""

from __future__ import annotations

import tomllib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


def read_toml(path: Path) -> dict[str, Any]:
    """Parse the TOML file at ``path``."""
    with path.open("rb") as handle:
        return tomllib.load(handle)


__all__ = ["read_toml"]
