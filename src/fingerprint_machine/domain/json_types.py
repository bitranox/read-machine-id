"""The JSON shapes a reading is made of.

A reading is built from WMI rows and registry values whose property sets are open by nature (a
new Windows build adds properties, a driver adds advanced settings), so its sections are plain
JSON rather than a fixed model. These aliases name that shape once, so every module agrees on it.

Contents:
    * :data:`JsonValue` - any JSON value.
    * :data:`JsonObject` - a JSON object.
"""

from __future__ import annotations

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None
type JsonObject = dict[str, JsonValue]

__all__ = ["JsonObject", "JsonValue"]
