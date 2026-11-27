r"""The BitLocker and TPM values WMI answers only through methods, beside each instance's properties.

``Win32_EncryptableVolume`` and ``Win32_Tpm`` hold their most telling values behind methods: a
volume's lock state and encryption percentage, its key protectors; the TPM's readiness, ownership
and dictionary-attack lockout. Each instance's row gets a ``methods`` object with one entry per
method, each the method's return value beside its out-parameters, or ``{"error": ...}`` when that
one call was refused.

Key protectors are recorded by TYPE only. ``GetKeyProtectors`` answers each protector's id, and
the id is needed once, to ask ``GetKeyProtectorType``; it stays in a local variable and never
reaches the reading, and neither does any recovery material (no method that reveals it is called,
and pwshpy refuses those anyway).

Contents:
    * :func:`bitlocker_volumes` - every encryptable volume with its method values.
    * :func:`tpm_with_methods` - the TPM with its method values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.cim_method import key_protector_name
from ..domain.machine_errors import SourceError
from .guard import guarded

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..domain.cim_method import CimArgument, CimMethodAnswer
    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import WindowsSources

_BITLOCKER = "root/cimv2/Security/MicrosoftVolumeEncryption"
_VOLUME = "Win32_EncryptableVolume"
_TPM_NAMESPACE = "root/cimv2/Security/MicrosoftTpm"
_TPM = "Win32_Tpm"
_VOLUME_METHODS = ("GetConversionStatus", "GetLockStatus", "GetProtectionStatus", "GetEncryptionMethod", "GetVersion")
_TPM_METHODS = (
    "IsReady",
    "IsOwned",
    "IsActivated",
    "IsEnabled",
    "IsEndorsementKeyPairPresent",
    "GetDictionaryAttackParameters",
    "GetCapLockoutInfo",
)


def _only(answers: list[CimMethodAnswer], call: str) -> CimMethodAnswer:
    if len(answers) != 1:
        raise SourceError(f"{call}: {len(answers)} instances answered, expected one")
    return answers[0]


def _ask(
    src: WindowsSources,
    call: tuple[str, str, str],
    *,
    where: str | None,
    arguments: Mapping[str, CimArgument] | None = None,
) -> CimMethodAnswer:
    namespace, class_name, method = call
    answers = src.platform.cim_method(class_name, method, namespace=namespace, where=where, arguments=arguments)
    return _only(answers, f"{class_name}.{method}")


def _device_where(device_id: str) -> str:
    r"""The WQL selecting one volume: a string literal doubles each backslash and escapes quotes.

    Example:
        >>> _device_where("\\\\?\\Volume{1}\\")
        "DeviceID = '\\\\\\\\?\\\\Volume{1}\\\\'"
    """
    literal = device_id.replace("\\", "\\\\").replace("'", "\\'")
    return f"DeviceID = '{literal}'"


def _protector_type(src: WindowsSources, where: str, protector_id: str) -> JsonValue:
    found = _ask(
        src, (_BITLOCKER, _VOLUME, "GetKeyProtectorType"), where=where, arguments={"VolumeKeyProtectorID": protector_id}
    )
    kind = found.out.get("KeyProtectorType")
    if found.return_value != 0 or not isinstance(kind, int):
        return {"return_value": found.return_value}
    return {"type": kind, "name": key_protector_name(kind)}


def _key_protector_types(src: WindowsSources, where: str) -> JsonValue:
    found = _ask(src, (_BITLOCKER, _VOLUME, "GetKeyProtectors"), where=where)
    if found.return_value != 0:
        return {"return_value": found.return_value}
    ids = found.out.get("VolumeKeyProtectorID")
    protector_ids = [i for i in ids if isinstance(i, str)] if isinstance(ids, list) else []
    return [guarded(lambda pid=pid: _protector_type(src, where, pid)) for pid in protector_ids]


def _volume_methods(src: WindowsSources, device_id: str) -> JsonObject:
    where = _device_where(device_id)
    methods: JsonObject = {
        name: guarded(lambda name=name: _ask(src, (_BITLOCKER, _VOLUME, name), where=where).as_json())
        for name in _VOLUME_METHODS
    }
    methods["key_protector_types"] = guarded(lambda: _key_protector_types(src, where))
    return methods


def bitlocker_volumes(src: WindowsSources) -> JsonValue:
    """Return every encryptable volume's properties with its method values under ``methods``.

    Raises:
        SourceError: the volumes cannot be listed (one method refused costs only its entry).
    """
    out: list[JsonValue] = []
    for volume in src.platform.cim(_VOLUME, namespace=_BITLOCKER):
        device_id = volume.get("DeviceID")
        if not isinstance(device_id, str):
            out.append({**volume, "methods": {"error": "SourceError: the volume has no DeviceID to select it by"}})
            continue
        out.append({**volume, "methods": _volume_methods(src, device_id)})
    return out


def tpm_with_methods(src: WindowsSources) -> JsonValue:
    """Return the TPM's properties with its method values under ``methods``.

    Raises:
        SourceError: the TPM class cannot be read (one method refused costs only its entry).
    """
    out: list[JsonValue] = []
    for row in src.platform.cim(_TPM, namespace=_TPM_NAMESPACE):
        methods: JsonObject = {
            name: guarded(lambda name=name: _ask(src, (_TPM_NAMESPACE, _TPM, name), where=None).as_json())
            for name in _TPM_METHODS
        }
        out.append({**row, "methods": methods})
    return out


__all__ = ["bitlocker_volumes", "tpm_with_methods"]
