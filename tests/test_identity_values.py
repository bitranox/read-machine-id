"""Identity helpers: PVSCSI sasWWID, product-key masking, MSDM, TBS, machine SID, certificates."""

from __future__ import annotations

import json
import struct
from typing import TYPE_CHECKING

import pytest
from machine_builder import PLANTED_KEY, PVSCSI_SERIAL, PVSCSI_WWID, acpi_table, ek_certificate_der, store_blob

from read_machine_id.domain.certificates import der_from_store_blob, describe_certificate
from read_machine_id.domain.identity import (
    WITHHELD,
    decode_acpi_header,
    decode_tbs_device_info,
    machine_sid,
    mask_product_keys,
    msdm_product_key,
    vmware_pvscsi_sas_wwid,
    withhold_registry_values,
)

if TYPE_CHECKING:
    from read_machine_id.domain.json_types import JsonObject

_PVSCSI = r"PCI\VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02"


@pytest.mark.os_agnostic
def test_pvscsi_serial_gives_back_the_sas_wwid() -> None:
    assert vmware_pvscsi_sas_wwid(f"{_PVSCSI}\\{PVSCSI_SERIAL}") == PVSCSI_WWID


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "pnp_id",
    [
        rf"PCI\VEN_8086&DEV_10D3\{PVSCSI_SERIAL}",  # not a PVSCSI controller
        rf"{_PVSCSI}\3&61AAA01&0&A0",  # an instance id with no serial number
        rf"{_PVSCSI}\0123ABCD50050560FF",  # wrong trailing byte
        None,
    ],
)
def test_anything_else_gives_no_sas_wwid(pnp_id: str | None) -> None:
    assert vmware_pvscsi_sas_wwid(pnp_id) is None


@pytest.mark.os_agnostic
def test_a_planted_product_key_never_survives_masking() -> None:
    tree: JsonObject = {"a": f"key {PLANTED_KEY}.", "b": [PLANTED_KEY.lower(), {"c": PLANTED_KEY}], "n": 5}
    text = json.dumps(mask_product_keys(tree))
    assert PLANTED_KEY not in text
    assert PLANTED_KEY.lower() not in text
    assert text.count("*****-*****-*****-*****-" + PLANTED_KEY[-5:]) == 2


@pytest.mark.os_agnostic
def test_digital_product_id_is_withheld() -> None:
    values = withhold_registry_values({"ProductId": "00330-1", "DigitalProductId": "a4", "DigitalProductId4": "f8"})
    assert values == {"ProductId": "00330-1", "DigitalProductId": WITHHELD, "DigitalProductId4": WITHHELD}


@pytest.mark.os_agnostic
def test_msdm_key_is_reported_masked() -> None:
    table = acpi_table(b"MSDM", bytes(20) + PLANTED_KEY.encode())
    assert msdm_product_key(table) == {"present": True, "product_key": "*****-*****-*****-*****-" + PLANTED_KEY[-5:]}


@pytest.mark.os_agnostic
def test_acpi_header_names_its_oem() -> None:
    header = decode_acpi_header(acpi_table(b"FACP"))
    assert (header["signature"], header["oem_id"], header["oem_table_id"], header["length"]) == (
        "FACP",
        "OEMID",
        "TABLEID",
        36,
    )


@pytest.mark.os_agnostic
def test_tbs_device_info_with_an_unknown_interface_is_named_so() -> None:
    info = decode_tbs_device_info(struct.pack("<IIII", 1, 2, 9, 1))
    assert (info["tpm_version"], info["interface"]) == ("2.0", "unknown(9)")


@pytest.mark.os_agnostic
def test_machine_sid_drops_the_rid() -> None:
    assert machine_sid([None, "S-1-5-18", "S-1-5-21-1-2-3-1001"]) == "S-1-5-21-1-2-3"


@pytest.mark.os_agnostic
def test_an_ek_certificate_is_read_from_its_store_blob() -> None:
    der = ek_certificate_der()
    assert der_from_store_blob(store_blob(der)) == der
    described = describe_certificate(der)
    assert described["subject"] == "CN=Synthetic EK"
    assert described["serial"] == "1234ABCD"
    assert described["not_before"] == "2024-01-01T00:00:00+00:00"
    assert len(str(described["sha256"])) == 64


@pytest.mark.os_agnostic
def test_a_store_blob_whose_record_overruns_it_has_no_certificate() -> None:
    blob = struct.pack("<III", 32, 1, 1000) + b"short"
    assert der_from_store_blob(blob) is None
