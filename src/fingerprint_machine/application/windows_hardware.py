r"""Windows readers for the cpu, memory, disks and devices sections that ask more than one question.

* ``cpu.cpus``: every logical processor Windows describes under
  ``HARDWARE\DESCRIPTION\System\CentralProcessor\<N>``, as Linux lists ``/sys/devices/system/cpu``.
* ``memory.numa``: the NUMA nodes and their processors (kernel32; client editions have no
  ``Win32_NumaNode`` class).
* ``disks.scsi``: the SCSI device map (``HARDWARE\DEVICEMAP\Scsi``) port by port, bus by bus,
  target by target, each logical unit with its decoded INQUIRY answer (vendor, model, rev, type,
  the names a Linux reading uses) and its Device Identification page.
* ``devices.displays``: every monitor Windows has seen, its EDID decoded (manufacturer, product,
  serial, name, year), as Linux lists ``/sys/class/drm``.

Each item is read on its own and guarded, so one unreadable processor, logical unit or monitor
costs only its own entry.

Contents:
    * :func:`read_cpus`, :func:`read_numa`, :func:`read_scsi_map`, :func:`read_displays`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..domain.edid import decode_edid
from ..domain.machine_errors import MissingKeyError
from ..domain.scsi_inquiry import decode_inquiry
from ..domain.vpd import decode_vpd_page83
from .guard import guarded
from .windows_values import optional_subkeys, values

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import WindowsSources

_PROCESSORS = r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor"
_SCSI = r"HKLM\HARDWARE\DEVICEMAP\Scsi"
_DISPLAY = r"HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY"
# The lookbehind keeps search from retrying inside a run of digits not at the end: each such
# start rescanned the run, so a long one cost the square of its length.
_NUMBER = re.compile(r"(?<!\d)(\d+)\s*$")


def _number(name: str) -> int | None:
    match = _NUMBER.search(name)
    return int(match.group(1)) if match is not None else None


def _numbered(names: list[str], prefix: str = "") -> list[tuple[int, str]]:
    """The subkeys named ``<prefix><number>``, in numeric order (``Scsi Port 10`` after ``2``)."""
    found = [(n, name) for name in names if name.startswith(prefix) and (n := _number(name)) is not None]
    return sorted(found)


def read_cpus(src: WindowsSources) -> JsonValue:
    """Read every processor's registry description, in processor order."""
    out: list[JsonValue] = []
    for number, name in _numbered(src.registry.subkeys(_PROCESSORS)):
        key = rf"{_PROCESSORS}\{name}"
        out.append({"cpu": number, "registry": guarded(lambda key=key: values(src, key))})
    return out


def read_numa(src: WindowsSources) -> JsonValue:
    """Read every NUMA node with its processor group and processors."""
    nodes: list[JsonValue] = [node.as_json() for node in src.platform.numa_nodes()]
    return nodes


def _binary(found: Mapping[str, object], name: str, decode: Callable[[bytes], JsonValue]) -> JsonValue:
    data = found.get(name)
    return decode(data) if isinstance(data, bytes) else None


def _inquiry(data: bytes) -> JsonValue:
    return decode_inquiry(data).as_json()


def _designators(page: bytes) -> JsonValue:
    found: list[JsonValue] = [d.as_json() for d in decode_vpd_page83(page)]
    return found


def _unit(src: WindowsSources, key: str) -> JsonObject:
    found = src.registry.values(key)
    return {
        "inquiry": guarded(lambda: _binary(found, "InquiryData", _inquiry)),
        "vpd_identifiers": guarded(lambda: _binary(found, "DeviceIdentifierPage", _designators)),
        "values": values(src, key),
    }


#: The SCSI map's levels: the name each is recorded under, and the prefix of its subkeys. A bus
#: also lists its own adapter (``Initiator Id 7``), which is no target and is left out.
_PORT, _BUS, _TARGET, _UNIT = (
    ("port", "Scsi Port "),
    ("bus", "Scsi Bus "),
    ("target", "Target Id "),
    ("lun", "Logical Unit Id "),
)


def _children(
    src: WindowsSources, key: str, level: tuple[str, str], read: Callable[[str], JsonObject]
) -> list[JsonValue]:
    """Each subkey of ``key`` at ``level`` (``Target Id 0``, ...) as ``{name: N, **read(path)}``, guarded."""
    out: list[JsonValue] = []
    name_of, prefix = level
    for number, name in _numbered(optional_subkeys(src, key), prefix):
        path = rf"{key}\{name}"
        answer = guarded(lambda path=path: read(path))
        out.append({name_of: number, **answer} if isinstance(answer, dict) else {name_of: number, "error": answer})
    return out


def _target(src: WindowsSources, key: str) -> JsonObject:
    return {"units": _children(src, key, _UNIT, lambda path: _unit(src, path))}


def _bus(src: WindowsSources, key: str) -> JsonObject:
    return {"targets": _children(src, key, _TARGET, lambda path: _target(src, path))}


def _port(src: WindowsSources, key: str) -> JsonObject:
    return {"values": values(src, key), "buses": _children(src, key, _BUS, lambda path: _bus(src, path))}


def read_scsi_map(src: WindowsSources) -> JsonValue:
    """Read the SCSI device map, port by port, down to each logical unit's INQUIRY answer."""
    ports: list[JsonValue] = _children(src, _SCSI, _PORT, lambda path: _port(src, path))
    return ports


def _edid(src: WindowsSources, key: str) -> JsonValue:
    """The monitor's EDID decoded; None when Windows stored none (a generic or virtual display)."""
    try:
        data = src.registry.values(rf"{key}\Device Parameters").get("EDID")
    except MissingKeyError:
        return None
    return decode_edid(data) if isinstance(data, bytes) else None


def _display(src: WindowsSources, instance_id: str) -> JsonObject:
    key = rf"HKLM\SYSTEM\CurrentControlSet\Enum\{instance_id}"
    found = values(src, key)
    return {
        "instance_id": instance_id,
        "name": found.get("FriendlyName") or found.get("DeviceDesc"),
        "driver": found.get("Driver"),
        "edid": guarded(lambda: _edid(src, key)),
    }


def read_displays(src: WindowsSources) -> JsonValue:
    """Read every monitor Windows has an instance for, present or not, its EDID decoded."""
    out: list[JsonValue] = []
    for model in optional_subkeys(src, _DISPLAY):
        for inst in optional_subkeys(src, rf"{_DISPLAY}\{model}"):
            instance_id = rf"DISPLAY\{model}\{inst}"
            out.append(guarded(lambda i=instance_id: _display(src, i)))
    return out


__all__ = ["read_cpus", "read_displays", "read_numa", "read_scsi_map"]
