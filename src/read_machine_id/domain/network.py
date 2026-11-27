"""Join the many Windows views of a network adapter into one record per adapter.

Windows spreads one network card over a dozen CIM classes. The ``MSFT_NetAdapter*SettingData``
classes (hardware location, advanced properties, RSS, offloads, ...) name the adapter by its
``Name``; the IP stack and the older ``Win32_*`` classes name it by ``InterfaceIndex``; the
driver's class registry key names it by ``NetCfgInstanceId``, which is ``MSFT_NetAdapter``'s
``DeviceID``. This module puts every row under the adapter it belongs to. A row that belongs to
no adapter (a hidden filter, an interface without a card) is kept under ``unmatched``.

Contents:
    * :data:`BY_NAME` - the categories joined by adapter name.
    * :data:`BY_INDEX` - the categories joined by interface index.
    * :func:`join_adapters` - one record per adapter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from .json_types import JsonObject, JsonValue

#: Category -> the CIM class it comes from; joined on ``Name``.
BY_NAME: Mapping[str, str] = {
    "hardware": "MSFT_NetAdapterHardwareInfoSettingData",
    "advanced_properties": "MSFT_NetAdapterAdvancedPropertySettingData",
    "rss": "MSFT_NetAdapterRssSettingData",
    "lso": "MSFT_NetAdapterLsoSettingData",
    "checksum_offload": "MSFT_NetAdapterChecksumOffloadSettingData",
    "rsc": "MSFT_NetAdapterRscSettingData",
    "vmq": "MSFT_NetAdapterVmqSettingData",
    "sriov": "MSFT_NetAdapterSriovSettingData",
    "power_management": "MSFT_NetAdapterPowerManagementSettingData",
    "bindings": "MSFT_NetAdapterBindingSettingData",
}

#: Category -> the CIM class it comes from; joined on ``InterfaceIndex``.
BY_INDEX: Mapping[str, str] = {
    "wmi_adapter": "Win32_NetworkAdapter",
    "wmi_configuration": "Win32_NetworkAdapterConfiguration",
    "ip_interfaces": "MSFT_NetIPInterface",
    "ip_addresses": "MSFT_NetIPAddress",
    "routes": "MSFT_NetRoute",
    "dns_servers": "MSFT_DNSClientServerAddress",
    "connection_profile": "MSFT_NetConnectionProfile",
}


def _upper(value: JsonValue) -> str | None:
    return value.upper() if isinstance(value, str) else None


def _join(
    adapters: Sequence[JsonObject],
    rows: Sequence[JsonObject],
    *,
    row_key: str,
    adapter_key: str,
) -> tuple[list[list[JsonValue]], list[JsonValue]]:
    """Distribute ``rows`` over ``adapters``; return each adapter's rows and the leftovers."""
    position = {a.get(adapter_key): i for i, a in enumerate(adapters) if a.get(adapter_key) is not None}
    per_adapter: list[list[JsonValue]] = [[] for _ in adapters]
    unmatched: list[JsonValue] = []
    for row in rows:
        index = position.get(row.get(row_key))
        if index is None:
            unmatched.append(row)
        else:
            per_adapter[index].append(row)
    return per_adapter, unmatched


def _class_key(adapter: JsonObject, class_keys: Mapping[str, JsonObject]) -> JsonValue:
    guid = _upper(adapter.get("DeviceID"))
    return class_keys.get(guid) if guid is not None else None


def join_adapters(
    adapters: Sequence[JsonObject],
    categories: Mapping[str, Sequence[JsonObject]],
    class_keys: Mapping[str, JsonObject],
) -> JsonObject:
    """Return one record per adapter with every category's rows, plus what matched no adapter.

    Args:
        adapters: the ``MSFT_NetAdapter`` rows.
        categories: rows per category name of :data:`BY_NAME` and :data:`BY_INDEX`; a category
            missing here is left out of every record.
        class_keys: the driver class registry keys by upper-case ``NetCfgInstanceId``, each
            ``{"number": "0001", "values": {...}}``.

    Returns:
        ``{"adapters": [...], "unmatched": {category: [rows]}}``.

    Examples:
        >>> ad = [{"Name": "Ethernet", "InterfaceIndex": 4, "DeviceID": "{a}"}]
        >>> cats = {"hardware": [{"Name": "Ethernet", "BusNumber": 3}, {"Name": "Ghost"}],
        ...         "ip_addresses": [{"InterfaceIndex": 4, "IPAddress": "192.0.2.1"}]}
        >>> out = join_adapters(ad, cats, {"{A}": {"number": "0001", "values": {}}})
        >>> rec = out["adapters"][0]
        >>> rec["hardware"], rec["ip_addresses"], rec["class_key"]["number"]
        ([{'Name': 'Ethernet', 'BusNumber': 3}], [{'InterfaceIndex': 4, 'IPAddress': '192.0.2.1'}], '0001')
        >>> out["unmatched"]
        {'hardware': [{'Name': 'Ghost'}]}
    """
    records: list[JsonObject] = [{"adapter": a, "class_key": _class_key(a, class_keys)} for a in adapters]
    unmatched: JsonObject = {}
    keyed = [(name, "Name", "Name") for name in BY_NAME] + [
        (name, "InterfaceIndex", "InterfaceIndex") for name in BY_INDEX
    ]
    for category, row_key, adapter_key in keyed:
        rows = categories.get(category)
        if rows is None:
            continue
        per_adapter, leftover = _join(adapters, rows, row_key=row_key, adapter_key=adapter_key)
        for record, mine in zip(records, per_adapter, strict=True):
            record[category] = mine
        if leftover:
            unmatched[category] = leftover
    out_records: list[JsonValue] = list(records)
    return {"adapters": out_records, "unmatched": unmatched}


__all__ = ["BY_INDEX", "BY_NAME", "join_adapters"]
