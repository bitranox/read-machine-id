"""The fingerprint at a glance: the identity values of a reading, the same fields on both OSes.

Built only from sections already read, so it asks the machine nothing and cannot disagree with
them. A section that was not read, or failed, leaves its summary fields None. Each OS has its own
builder (:mod:`.summary_windows`, :mod:`.summary_linux`) filling one record type
(:mod:`.summary_model`), so the summaries of one machine read under Windows and under Linux
compare field by field.

Contents:
    * :func:`summarize` - the summary of a reading's sections, as JSON.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .enums import MachineOs
from .summary_linux import summarize_linux
from .summary_windows import summarize_windows

if TYPE_CHECKING:
    from .json_types import JsonObject


def summarize(body: JsonObject, *, machine_os: MachineOs) -> JsonObject:
    """Return the identity values of a reading's sections, read the way ``machine_os`` records them.

    Examples:
        >>> s = summarize({"cpu": {"wmi": [{"Name": "Xeon", "NumberOfCores": 4}]}}, machine_os=MachineOs.WINDOWS)
        >>> s["cpu"]["name"], s["cpu"]["cores"], s["nics"], s["system"]["uuid"]
        ('Xeon', 4, [], None)
        >>> list(summarize({}, machine_os=MachineOs.LINUX))
        ['system', 'cpu', 'memory', 'nics', 'scsi_controllers', 'disks', 'os', 'windows', 'security']
    """
    builder = summarize_windows if machine_os is MachineOs.WINDOWS else summarize_linux
    return builder(body).as_json()


__all__ = ["summarize"]
