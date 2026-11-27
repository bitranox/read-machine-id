"""The registry source: lib_registry over the real registry on Windows.

lib_registry chooses its backend when it is imported: ``winreg`` on Windows, ``fake_winreg``
everywhere else. So on Linux this same adapter reads a fake registry, which is how the tests run
it for real; production only ever wires it on Windows.

Contents:
    * :class:`LibRegistrySource` - the production :class:`RegistrySource`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from lib_registry import Registry, RegistryError, RegistryKeyNotFoundError

from ...domain.machine_errors import MissingKeyError, SourceError

if TYPE_CHECKING:
    from ...application.machine_ports import RegistryData


class LibRegistrySource:
    """Read registry keys and values through one :class:`lib_registry.Registry`."""

    def __init__(self, registry: Registry | None = None) -> None:
        """Wrap ``registry``, or a new local one."""
        self._registry = registry if registry is not None else Registry()

    def values(self, key: str) -> dict[str, RegistryData]:
        """Return every value of ``key`` by name.

        Raises:
            MissingKeyError: the key does not exist.
            SourceError: the key cannot be opened.
        """
        try:
            return {v.name: v.data for v in self._registry.values(key)}
        except RegistryKeyNotFoundError as exc:
            raise MissingKeyError(f"{key}: {exc}") from exc
        except (RegistryError, OSError) as exc:
            raise SourceError(f"{key}: {exc}") from exc

    def subkeys(self, key: str) -> list[str]:
        """Return the subkey names of ``key``, sorted case-insensitively.

        Raises:
            MissingKeyError: the key does not exist.
            SourceError: the key cannot be opened.
        """
        try:
            return sorted(self._registry.subkeys(key), key=str.casefold)
        except RegistryKeyNotFoundError as exc:
            raise MissingKeyError(f"{key}: {exc}") from exc
        except (RegistryError, OSError) as exc:
            raise SourceError(f"{key}: {exc}") from exc


__all__ = ["LibRegistrySource"]
