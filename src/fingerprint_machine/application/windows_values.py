"""The building blocks every Windows reader uses: registry values as JSON, and reader factories.

A Windows section is a map of named readers; most of them ask one CIM class for every instance
or one registry key for every value. The factories here make those readers, and the helpers turn
registry data into JSON the same way everywhere (binary as hex).

A key that only some machines have (a policy key, a store that exists once something was set up)
is read through :func:`optional_values` / :func:`optional_subkeys`: its absence is an answer
(nothing configured), not a refusal.

Contents:
    * :data:`Reader` - one question asked of a Windows machine.
    * :func:`registry_json` - one registry value's data as JSON.
    * :func:`values`, :func:`value`, :func:`optional_values`, :func:`optional_subkeys` - registry reads.
    * :func:`cim`, :func:`reg`, :func:`reg_value`, :func:`optional_reg` - reader factories.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from ..domain.machine_errors import MissingKeyError
from .machine_ports import WindowsSources

if TYPE_CHECKING:
    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import RegistryData

#: The CIM namespace most classes live in.
CIMV2 = "root/cimv2"

#: One question asked of a Windows machine.
type Reader = Callable[[WindowsSources], JsonValue]


def registry_json(data: RegistryData) -> JsonValue:
    """Return one registry value's data as JSON: binary as hex, everything else as is.

    Examples:
        >>> registry_json(b"\\x01\\xff"), registry_json(["a"]), registry_json(5)
        ('01ff', ['a'], 5)
    """
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, list):
        items: list[JsonValue] = list(data)
        return items
    return data


def values(src: WindowsSources, key: str) -> JsonObject:
    """Return every value of ``key`` as JSON, by name.

    Raises:
        SourceError: the key does not exist (:class:`MissingKeyError`) or cannot be opened.
    """
    return {name: registry_json(data) for name, data in src.registry.values(key).items()}


def value(src: WindowsSources, key: str, name: str) -> JsonValue:
    """Return one value of ``key`` as JSON.

    Raises:
        KeyError: the key has no such value.
        SourceError: the key does not exist or cannot be opened.
    """
    return registry_json(src.registry.values(key)[name])


def optional_values(src: WindowsSources, key: str) -> JsonObject | None:
    """Return every value of a key only some machines have; None when this one has not got it."""
    try:
        return values(src, key)
    except MissingKeyError:
        return None


def optional_subkeys(src: WindowsSources, key: str) -> list[str]:
    """Return the subkeys of a key only some machines have; none when this one has not got it."""
    try:
        return src.registry.subkeys(key)
    except MissingKeyError:
        return []


def cim(class_name: str, namespace: str = CIMV2, where: str | None = None) -> Reader:
    """Return a reader for every instance of a CIM class."""

    def read(src: WindowsSources) -> JsonValue:
        rows: list[JsonValue] = list(src.platform.cim(class_name, namespace=namespace, where=where))
        return rows

    return read


def reg(key: str) -> Reader:
    """Return a reader for every value of a registry key."""
    return lambda src: values(src, key)


def optional_reg(key: str) -> Reader:
    """Return a reader for every value of a key only some machines have (None when absent)."""
    return lambda src: optional_values(src, key)


def reg_value(key: str, name: str) -> Reader:
    """Return a reader for one registry value."""
    return lambda src: value(src, key, name)


__all__ = [
    "CIMV2",
    "Reader",
    "cim",
    "optional_reg",
    "optional_subkeys",
    "optional_values",
    "reg",
    "reg_value",
    "registry_json",
    "value",
    "values",
]
