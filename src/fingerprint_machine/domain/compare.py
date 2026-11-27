"""Compare two readings field by field, and score how much of the machine is identical.

A reading is a tree of JSON. Comparing flattens both trees into ``dotted.path -> value`` pairs
and gives every path one :class:`FieldStatus`. Two kinds of path are shown but not scored,
because their difference says nothing about the machine:

* volatile paths: counters and clocks that change between two readings of the same machine
  (free memory, uptime, lease expiry, interrupt counts). They are named twice: by path prefix for
  a whole branch, matched on the path's shape (list indexes stripped, so one entry covers every
  device), and by leaf name for a property that turns up in many WMI classes.
* paths only one side has when the two readings come from different schema versions: a newer
  reader collects fields an older one never asked for, and the older baseline cannot be
  re-collected once the machine it came from is gone.

Contents:
    * :class:`FieldStatus` - the status of one compared field.
    * :class:`FieldRow` - one compared field.
    * :class:`Comparison` - all compared fields.
    * :func:`flatten` - a JSON tree as ``(path, value)`` pairs.
    * :func:`compare_readings` - compare two readings.
    * :func:`score` - the counts and the identical share.
    * :func:`comparison_document` - the comparison as JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from .sources import path_shape, source_of

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from .json_types import JsonObject, JsonValue

# /proc/meminfo counters; the sizes beside them (MemTotal, SwapTotal, Hugepagesize, ...) stay scored.
_MEMINFO_COUNTERS = (
    "Active",
    "AnonHugePages",
    "AnonPages",
    "Bounce",
    "Buffers",
    "Cached",
    "CmaFree",
    "Committed_AS",
    "Dirty",
    "FileHugePages",
    "FilePmdMapped",
    "HugePages_Free",
    "HugePages_Rsvd",
    "HugePages_Surp",
    "Inactive",
    "KReclaimable",
    "KernelStack",
    "Mapped",
    "MemAvailable",
    "MemFree",
    "Mlocked",
    "NFS_Unstable",
    "PageTables",
    "Percpu",
    "SReclaimable",
    "SUnreclaim",
    "SecPageTables",
    "Shmem",
    "Slab",
    "SwapCached",
    "SwapFree",
    "Unaccepted",
    "Unevictable",
    "VmallocUsed",
    "Writeback",
    "Zswap",
)

#: Branches whose every value changes between readings of one machine, matched on the path's
#: shape (list indexes stripped). Leaf 1 EBX is volatile whole: bits 31:24 are the initial APIC id
#: of whichever CPU ran the read, and a raw register is recorded as read, never masked.
VOLATILE_PREFIXES = (
    "meta.",
    "windows.last_boot",
    "windows.uptime_s",
    "platform.boot_id",
    "cpuid.raw.0x00000001:0.ebx",
    "pci.devices[].power_state",
    "pci.devices[].config.header.status",
    "network.adapters[].neighbours",
    "network.tables.neighbours",
    "devices.modules[].refcount",
    "security.ima.runtime_measurements_count",
    # A service's run state, not its configuration: trigger-start services start and stop on an
    # idle machine, and each start gets a new process id. StartMode and the rest stay scored.
    "services.all[].ProcessId",
    "services.all[].State",
    "services.all[].Started",
    "services.all[].AcceptStop",
    "services.all[].AcceptPause",
    "windows.licensing_products[].TrustedTime",
    # Measured changing on every reading of one idle Windows VM; Microsoft does not document it.
    "cpu.cpus[].registry.Patch Configuration Used",
    *(f"memory.meminfo.{name}" for name in _MEMINFO_COUNTERS),
)

#: Property names that are counters or clocks wherever they occur.
VOLATILE_KEYS = frozenset(
    {
        "AntispywareSignatureAge",
        "AntispywareSignatureLastUpdated",
        "AntivirusSignatureAge",
        "AntivirusSignatureLastUpdated",
        "CurrentClockSpeed",
        "CurrentUsage",
        "CurrentVoltage",
        "DHCPLeaseExpires",
        "DHCPLeaseObtained",
        "FreePhysicalMemory",
        "FreeSpace",
        "FreeSpaceInPagingFiles",
        "FreeVirtualMemory",
        "FullScanAge",
        "FullScanEndTime",
        "FullScanStartTime",
        "GracePeriodRemaining",
        "LastBootUpTime",
        "LoadPercentage",
        "LocalDateTime",
        "LsaPid",
        "NISSignatureAge",
        "NISSignatureLastUpdated",
        "NumberOfProcesses",
        "NumberOfUsers",
        "PeakUsage",
        "PreferredLifetime",
        "QuickScanAge",
        "QuickScanEndTime",
        "QuickScanStartTime",
        "SizeRemaining",
        "TimeOfLastReset",
        "ValidLifetime",
        "cpu_mhz",
        "cpuinfo_cur_freq",
        "per_cpu_counts",
        "scaling_cur_freq",
    }
)


class FieldStatus(StrEnum):
    """How one field of the two readings compares."""

    SAME = "same"
    DIFF = "diff"
    ONLY_ORIGINAL = "only-original"
    ONLY_ACTUAL = "only-actual"
    VOLATILE = "volatile"
    NEWER_PROBE_ONLY = "newer-probe-only"


#: The statuses that count towards the score.
SCORED = (FieldStatus.SAME, FieldStatus.DIFF, FieldStatus.ONLY_ORIGINAL, FieldStatus.ONLY_ACTUAL)
#: The statuses that mean the machine looks different.
DIFFERING = (FieldStatus.DIFF, FieldStatus.ONLY_ORIGINAL, FieldStatus.ONLY_ACTUAL)


@dataclass(frozen=True)
class FieldRow:
    """One compared field: its path, both values, its status and the hardware field it comes from."""

    path: str
    original: JsonValue
    actual: JsonValue
    status: FieldStatus
    source: str | None = None


@dataclass
class Comparison:
    """Every compared field, in path order."""

    rows: list[FieldRow] = field(default_factory=list["FieldRow"])

    def counts(self) -> dict[str, int]:
        """Return how many fields have each status."""
        out: dict[str, int] = {}
        for row in self.rows:
            out[row.status.value] = out.get(row.status.value, 0) + 1
        return out

    def differences(self) -> list[str]:
        """Return the paths whose status says the machine looks different."""
        return [row.path for row in self.rows if row.status in DIFFERING]


def flatten(data: JsonValue, prefix: str = "") -> Iterator[tuple[str, JsonValue]]:
    """Yield ``(dotted.path, value)`` pairs; a list of scalars stays one value.

    Examples:
        >>> list(flatten({"a": {"b": 1, "c": [1, 2]}, "d": [{"e": 3}]}))
        [('a.b', 1), ('a.c', [1, 2]), ('d[0].e', 3)]
    """
    if isinstance(data, dict):
        for key, value in data.items():
            yield from flatten(value, f"{prefix}.{key}" if prefix else key)
    elif isinstance(data, list) and any(isinstance(x, (dict, list)) for x in data):
        for i, value in enumerate(data):
            yield from flatten(value, f"{prefix}[{i}]")
    else:
        yield prefix, data


def is_volatile(path: str) -> bool:
    """Return whether a path changes between readings of one machine.

    Examples:
        >>> is_volatile("meta.collected_at"), is_volatile("platform.os[0].FreePhysicalMemory")
        (True, True)
        >>> is_volatile("smbios.system.uuid")
        False
    """
    if path_shape(path).startswith(VOLATILE_PREFIXES):
        return True
    leaf = path.rsplit(".", 1)[-1].split("[", 1)[0]
    return leaf in VOLATILE_KEYS


def schema_version(reading: Mapping[str, JsonValue]) -> JsonValue:
    """Return the schema version a reading records, or None for one that records none.

    Version-1 readings (the predecessor script) recorded it as ``probe_version``.

    Examples:
        >>> schema_version({"meta": {"schema_version": 2}}), schema_version({"meta": {"probe_version": 1}})
        (2, 1)
        >>> schema_version({}) is None
        True
    """
    meta = reading.get("meta")
    if not isinstance(meta, dict):
        return None
    return meta.get("schema_version", meta.get("probe_version"))


def _status(path: str, *, in_a: bool, in_b: bool, same_schema: bool) -> FieldStatus:
    if is_volatile(path):
        return FieldStatus.VOLATILE
    if in_a and in_b:
        return FieldStatus.SAME
    if not same_schema:
        return FieldStatus.NEWER_PROBE_ONLY
    return FieldStatus.ONLY_ACTUAL if in_b else FieldStatus.ONLY_ORIGINAL


def compare_readings(a: JsonObject, b: JsonObject) -> Comparison:
    """Compare two readings path by path.

    Examples:
        >>> c = compare_readings({"x": {"y": 1, "z": 2}}, {"x": {"y": 1, "z": 3, "w": 4}})
        >>> [(r.path, r.status.value) for r in c.rows]
        [('x.w', 'only-actual'), ('x.y', 'same'), ('x.z', 'diff')]
        >>> old = {"meta": {"probe_version": 1}, "x": 1}
        >>> new = {"meta": {"schema_version": 2}, "x": 1, "y": 2}
        >>> [(r.path, r.status.value) for r in compare_readings(old, new).rows if r.path == "y"]
        [('y', 'newer-probe-only')]
    """
    fa, fb = dict(flatten(a)), dict(flatten(b))
    same_schema = schema_version(a) == schema_version(b)
    out = Comparison()
    for path in sorted(set(fa) | set(fb)):
        va, vb = fa.get(path), fb.get(path)
        status = _status(path, in_a=path in fa, in_b=path in fb, same_schema=same_schema)
        if status is FieldStatus.SAME and va != vb:
            status = FieldStatus.DIFF
        out.rows.append(FieldRow(path, va, vb, status, source_of(path)))
    return out


def score(cmp: Comparison) -> JsonObject:
    """Return the status counts, how many fields were scored, and the identical share.

    Examples:
        >>> s = score(compare_readings({"a": 1, "b": 2}, {"a": 1, "b": 3}))
        >>> s["scored"], s["identical"], s["identical_pct"]
        (2, 1, 50.0)
    """
    counts = cmp.counts()
    scored = sum(counts.get(status.value, 0) for status in SCORED)
    same = counts.get(FieldStatus.SAME.value, 0)
    counts_json: JsonObject = dict(counts)
    return {
        "counts": counts_json,
        "scored": scored,
        "identical": same,
        "identical_pct": round(100.0 * same / scored, 1) if scored else 0.0,
    }


def comparison_document(cmp: Comparison, labels: tuple[str, str]) -> JsonObject:
    """Return the comparison as JSON: the score, the differing paths and every row.

    Examples:
        >>> doc = comparison_document(compare_readings({"x": 1}, {"x": 2}), ("vmware", "kvm"))
        >>> doc["rows"], doc["differences"]
        ([{'field': 'x', 'original': 1, 'actual': 2, 'status': 'diff', 'source': None}], ['x'])
    """
    rows: list[JsonValue] = [
        {"field": r.path, "original": r.original, "actual": r.actual, "status": r.status.value, "source": r.source}
        for r in cmp.rows
    ]
    differences: list[JsonValue] = list(cmp.differences())
    return {
        "original": labels[0],
        "actual": labels[1],
        **score(cmp),
        "differences": differences,
        "rows": rows,
    }


__all__ = [
    "DIFFERING",
    "SCORED",
    "VOLATILE_KEYS",
    "VOLATILE_PREFIXES",
    "Comparison",
    "FieldRow",
    "FieldStatus",
    "compare_readings",
    "comparison_document",
    "flatten",
    "is_volatile",
    "schema_version",
    "score",
]
