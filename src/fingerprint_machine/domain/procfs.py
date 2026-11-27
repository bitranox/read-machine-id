"""Parse the text files Linux describes itself in: ``/proc/cpuinfo``, ``/proc/meminfo``, ``/proc/modules``
and ``/etc/os-release``.

Each parser takes the whole text of one file and never raises on a line it does not understand:
it skips the line, so a kernel that adds a field or a distribution that writes an odd line costs
that line only.

Contents:
    * :func:`parse_cpuinfo` - one object per logical CPU.
    * :func:`parse_meminfo` - every counter, kilobytes turned into bytes.
    * :func:`parse_module_names` - the loaded kernel modules.
    * :func:`parse_os_release` - the ``KEY=value`` pairs of an os-release file.
    * :func:`parse_choice` - a sysfs choice file (``none [integrity] confidentiality``).
    * :func:`parse_apparmor_modes` - how many AppArmor profiles run in each mode.
"""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject, JsonValue

#: cpuinfo fields that are space-separated lists of names.
_LIST_FIELDS = frozenset({"flags", "bugs", "vmx_flags", "power_management"})
_KILOBYTE = 1024


def _cpuinfo_key(name: str) -> str:
    return "_".join(name.strip().lower().split())


def _cpuinfo_value(key: str, value: str) -> JsonValue:
    if key in _LIST_FIELDS:
        names: list[JsonValue] = list(value.split())
        return names
    return value.strip()


def parse_cpuinfo(text: str) -> list[JsonObject]:
    """Return one object per logical CPU block of ``/proc/cpuinfo``.

    Keys are the field names in lower case with spaces as underscores (``model name`` becomes
    ``model_name``); ``flags``, ``bugs``, ``vmx flags`` and ``power management`` are lists of
    names, every other value is the text after the colon.

    Example:
        >>> parse_cpuinfo("processor\\t: 0\\nflags\\t\\t: fpu vme\\n\\n")
        [{'processor': '0', 'flags': ['fpu', 'vme']}]
    """
    cpus: list[JsonObject] = []
    current: JsonObject = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                cpus.append(current)
            current = {}
            continue
        name, colon, value = line.partition(":")
        if colon:
            key = _cpuinfo_key(name)
            current[key] = _cpuinfo_value(key, value)
    if current:
        cpus.append(current)
    return cpus


def _meminfo_value(fields: list[str]) -> int | None:
    if not fields or not fields[0].isdigit():
        return None
    number = int(fields[0])
    return number * _KILOBYTE if fields[1:] == ["kB"] else number


def parse_meminfo(text: str) -> JsonObject:
    """Return every counter of ``/proc/meminfo``: ``kB`` values in bytes, the rest as counts.

    Example:
        >>> parse_meminfo("MemTotal:  2 kB\\nHugePages_Free:  3\\n")
        {'MemTotal': 2048, 'HugePages_Free': 3}
    """
    counters: JsonObject = {}
    for line in text.splitlines():
        name, colon, rest = line.partition(":")
        value = _meminfo_value(rest.split()) if colon else None
        if value is not None:
            counters[name.strip()] = value
    return counters


def parse_module_names(text: str) -> list[str]:
    """Return the name of every module ``/proc/modules`` lists, in its order.

    Example:
        >>> parse_module_names("nf_tables 1 0 - Live 0x0\\n")
        ['nf_tables']
    """
    return [fields[0] for line in text.splitlines() if (fields := line.split())]


def _os_release_value(raw: str) -> str | None:
    try:
        words = shlex.split(raw, comments=False, posix=True)
    except ValueError:
        return None
    return " ".join(words)


def parse_os_release(text: str) -> JsonObject:
    """Return the ``KEY=value`` pairs of an os-release file, values unquoted as a shell would.

    Comments, blank lines and lines without ``=`` are skipped.

    Example:
        >>> parse_os_release('ID=example\\nNAME="Example Linux"\\n# note\\n')
        {'ID': 'example', 'NAME': 'Example Linux'}
    """
    pairs: JsonObject = {}
    for line in text.splitlines():
        stripped = line.strip()
        key, equals, raw = stripped.partition("=")
        if stripped.startswith("#") or not equals or not key.isidentifier():
            continue
        value = _os_release_value(raw)
        if value is not None:
            pairs[key] = value
    return pairs


def parse_choice(text: str) -> JsonObject:
    """Return a sysfs choice file: every choice, and the one in brackets as ``selected``.

    Example:
        >>> parse_choice("none [integrity] confidentiality\\n")
        {'selected': 'integrity', 'choices': ['none', 'integrity', 'confidentiality']}
    """
    words = text.split()
    choices: list[JsonValue] = [w.strip("[]") for w in words]
    selected = next((w.strip("[]") for w in words if w.startswith("[") and w.endswith("]")), None)
    return {"selected": selected, "choices": choices}


def parse_apparmor_modes(text: str) -> JsonObject:
    """Return how many loaded AppArmor profiles run in each mode (the profile names are left out).

    Each line of ``/sys/kernel/security/apparmor/profiles`` is ``<name> (<mode>)``.

    Example:
        >>> parse_apparmor_modes("a (enforce)\\nb (complain)\\nc (enforce)\\n")
        {'complain': 1, 'enforce': 2}
    """
    counts: dict[str, int] = {}
    for line in text.splitlines():
        head, paren, tail = line.rstrip().rpartition(" (")
        if head and paren and tail.endswith(")"):
            mode = tail[:-1]
            counts[mode] = counts.get(mode, 0) + 1
    return {mode: counts[mode] for mode in sorted(counts)}


__all__ = [
    "parse_apparmor_modes",
    "parse_choice",
    "parse_cpuinfo",
    "parse_meminfo",
    "parse_module_names",
    "parse_os_release",
]
