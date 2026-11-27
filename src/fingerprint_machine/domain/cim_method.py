"""What a CIM method call answers, and the BitLocker key protector types it can name.

Some WMI values exist only as method results: ``Win32_EncryptableVolume`` gives its lock state
and encryption percentage only through ``GetLockStatus`` and ``GetConversionStatus``, and
``Win32_Tpm`` its readiness and lockout state only through ``IsReady`` and
``GetDictionaryAttackParameters``. A method runs on one instance and answers a return value
(0 for success, a Win32 or WMI error code otherwise) plus its out-parameters.

Contents:
    * :data:`CimArgument` - the value types a method argument may take.
    * :class:`CimMethodAnswer` - one instance's answer to a method call.
    * :func:`key_protector_name` - the name of a BitLocker key protector type.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject

#: A method argument: text, a number or a flag, typed by the method's schema.
type CimArgument = str | int | bool

# Win32_EncryptableVolume.GetKeyProtectorType's KeyProtectorType values, from its documentation.
_KEY_PROTECTOR_TYPES: dict[int, str] = {
    0: "unknown or other",
    1: "trusted platform module",
    2: "external key",
    3: "numerical password",
    4: "tpm and pin",
    5: "tpm and startup key",
    6: "tpm and pin and startup key",
    7: "public key",
    8: "passphrase",
    9: "tpm certificate",
    10: "cng protector",
}


@dataclass(frozen=True, slots=True)
class CimMethodAnswer:
    """One instance's answer to a CIM method call.

    ``instance_path`` is the relative WMI path of the instance the method ran on;
    ``return_value`` is the method's own result (None for a method that declares none); ``out``
    holds the out-parameters as JSON.
    """

    instance_path: str
    return_value: int | None
    out: JsonObject

    def as_json(self) -> JsonObject:
        """Return the answer as a reading records it: the return value beside the out-parameters.

        Example:
            >>> CimMethodAnswer(instance_path="Win32_Tpm=@", return_value=0, out={"IsReady": True}).as_json()
            {'return_value': 0, 'IsReady': True}
        """
        return {"return_value": self.return_value, **self.out}


def key_protector_name(kind: int) -> str:
    """Return the name of a BitLocker key protector type, or ``type <n>`` for one not documented.

    Examples:
        >>> key_protector_name(1)
        'trusted platform module'
        >>> key_protector_name(42)
        'type 42'
    """
    return _KEY_PROTECTOR_TYPES.get(kind, f"type {kind}")


__all__ = ["CimArgument", "CimMethodAnswer", "key_protector_name"]
