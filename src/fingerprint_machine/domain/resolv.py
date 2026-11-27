"""The resolver configuration file, ``/etc/resolv.conf`` (resolv.conf(5)).

Contents:
    * :class:`ResolverConfig` - the resolvers, search domains and options a file names.
    * :func:`parse_resolv_conf` - read one file's text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject, JsonValue


@dataclass(frozen=True, slots=True)
class ResolverConfig:
    """What one resolver configuration file names, each list in file order."""

    nameservers: tuple[str, ...]
    domain: str | None
    search: tuple[str, ...]
    options: tuple[str, ...]
    sortlist: tuple[str, ...]

    def as_json(self) -> JsonObject:
        """Return the configuration as a reading records it."""
        nameservers: list[JsonValue] = list(self.nameservers)
        search: list[JsonValue] = list(self.search)
        options: list[JsonValue] = list(self.options)
        sortlist: list[JsonValue] = list(self.sortlist)
        return {
            "nameservers": nameservers,
            "domain": self.domain,
            "search": search,
            "options": options,
            "sortlist": sortlist,
        }


def _words(line: str) -> list[str]:
    # A comment starts with ';' or '#' anywhere on the line.
    for mark in ";#":
        line = line.split(mark, 1)[0]
    return line.split()


def parse_resolv_conf(text: str) -> ResolverConfig:
    """Return what a resolver configuration file names; unknown keywords are left out.

    As the resolver does, only the last ``search`` line counts.

    Example:
        >>> parse_resolv_conf("nameserver 192.0.2.53\\n").nameservers
        ('192.0.2.53',)
    """
    lists: dict[str, list[str]] = {"nameserver": [], "search": [], "options": [], "sortlist": []}
    domain: str | None = None
    for line in text.splitlines():
        words = _words(line)
        if not words:
            continue
        keyword, rest = words[0], words[1:]
        if keyword == "domain" and rest:
            domain = rest[0]
        elif keyword == "nameserver":
            lists["nameserver"].extend(rest[:1])
        elif keyword == "search":
            lists["search"] = rest  # only the last search line counts
        elif keyword in lists:
            lists[keyword].extend(rest)
    return ResolverConfig(
        nameservers=tuple(lists["nameserver"]),
        domain=domain,
        search=tuple(lists["search"]),
        options=tuple(lists["options"]),
        sortlist=tuple(lists["sortlist"]),
    )


__all__ = ["ResolverConfig", "parse_resolv_conf"]
