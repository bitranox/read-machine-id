"""The platform source of a real Windows machine: CIM through pwshpy, the rest through ctypes.

pwshpy queries WMI natively (no ``powershell.exe`` child, no text parsing), returns each
instance as an open property bag and runs the read-only CIM methods its allowlist names; this
adapter turns the bag into JSON and maps pwshpy's errors to :class:`SourceError`, so one class
missing on this Windows build costs one answer, not the reading.

Contents:
    * :func:`to_json` - any value pwshpy or ctypes hands back, as JSON.
    * :class:`PwshpyPlatformSource` - the production :class:`PlatformSource`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pwshpy import PwshPyError, ps

from ...domain.cim_method import CimMethodAnswer
from ...domain.machine_errors import SourceError
from ...domain.smbios import split_raw_smbios
from . import devnode, firmware, kernel

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ...domain.cim_method import CimArgument
    from ...domain.devprops import DeviceProperty
    from ...domain.json_types import JsonObject, JsonValue
    from ...domain.numa import NumaNode


def to_json(value: object) -> JsonValue:
    """Return ``value`` as JSON: bytes as hex, containers walked, anything else as its text.

    Examples:
        >>> to_json({"a": (1, b"\\x0f"), "b": None, "c": 1.5})
        {'a': [1, '0f'], 'b': None, 'c': 1.5}
        >>> to_json(object.__new__(type("Odd", (), {"__str__": lambda self: "odd"})))
        'odd'
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, dict):
        bag = cast("dict[object, object]", value)
        return {str(k): to_json(v) for k, v in bag.items()}
    if isinstance(value, (list, tuple)):
        items = cast("list[object] | tuple[object, ...]", value)
        return [to_json(v) for v in items]
    return str(value)


class PwshpyPlatformSource:
    """Answer CIM questions through pwshpy and firmware questions through ctypes."""

    def cim(self, class_name: str, *, namespace: str = "root/cimv2", where: str | None = None) -> list[JsonObject]:
        """Return every instance of ``class_name`` in ``namespace``.

        Raises:
            SourceError: the class, namespace or query failed.
        """
        try:
            rows = list(ps.get_cim_instance(class_name, where=where, namespace=namespace))
        except PwshPyError as exc:
            raise SourceError(f"{namespace}:{class_name}: {exc}") from exc
        out: list[JsonObject] = []
        for row in rows:
            bag = to_json(row.properties)
            if isinstance(bag, dict):
                out.append(bag)
        return out

    def cim_method(
        self,
        class_name: str,
        method_name: str,
        *,
        namespace: str = "root/cimv2",
        where: str | None = None,
        arguments: Mapping[str, CimArgument] | None = None,
    ) -> list[CimMethodAnswer]:
        """Run a read-only CIM method on every instance ``where`` selects.

        The error message names the class and method but never an argument: an argument can be a
        BitLocker protector id, which a reading must not carry.

        Raises:
            SourceError: pwshpy refused the method or WMI failed it.
        """
        try:
            results = list(
                ps.invoke_cim_method(class_name, method_name, where=where, namespace=namespace, arguments=arguments)
            )
        except PwshPyError as exc:
            raise SourceError(f"{namespace}:{class_name}.{method_name}: {exc}") from exc
        out: list[CimMethodAnswer] = []
        for result in results:
            bag = to_json(result.out_parameters)
            out.append(
                CimMethodAnswer(
                    instance_path=result.instance_path,
                    return_value=result.return_value,
                    out=bag if isinstance(bag, dict) else {},
                )
            )
        return out

    def smbios_table(self) -> tuple[bytes, str]:
        """Return the SMBIOS structure table and version from the firmware's RSMB block."""
        try:
            return split_raw_smbios(firmware.firmware_table(firmware.RSMB, 0))
        except ValueError as exc:
            raise SourceError(f"RSMB: {exc}") from exc

    def acpi_tables(self) -> list[bytes]:
        """Return every ACPI table the firmware exposes."""
        return [firmware.firmware_table(firmware.ACPI, tid) for tid in firmware.firmware_table_ids(firmware.ACPI)]

    def tbs_device_info(self) -> bytes:
        """Return TBS's TPM_DEVICE_INFO."""
        return firmware.tbs_device_info()

    def firmware_type(self) -> str:
        """Return the firmware type."""
        return firmware.firmware_type()

    def device_property(self, instance_id: str, prop: DeviceProperty) -> JsonValue:
        """Return one configuration-manager property of a device instance."""
        return devnode.device_property(instance_id, prop)

    def numa_nodes(self) -> list[NumaNode]:
        """Return every NUMA node."""
        return kernel.numa_nodes()

    def kernel_dma_protection(self) -> bool:
        """Return whether Kernel DMA Protection is in force."""
        return kernel.kernel_dma_protection()


__all__ = ["PwshpyPlatformSource", "to_json"]
