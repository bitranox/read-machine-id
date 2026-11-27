"""The pure EDID decoder, fed base blocks built from the VESA E-EDID 1.4 layout."""

from __future__ import annotations

import pytest
from edid_bytes import edid_block

from fingerprint_machine.domain.edid import decode_edid


@pytest.mark.os_agnostic
def test_a_block_gives_manufacturer_product_serial_name_and_date() -> None:
    data = edid_block(texts={0xFC: "Virtual Disp", 0xFF: "SN0001"}, extensions=1)
    assert decode_edid(data) == {
        "manufacturer": "VMW",
        "product_code": "0x0001",
        "serial_number": 0x01234567,
        "serial": "SN0001",
        "name": "Virtual Disp",
        "text": None,
        "week": 12,
        "year": 2020,
        "model_year": False,
        "version": "1.4",
        "extensions": 1,
        "checksum_ok": True,
    }


@pytest.mark.os_agnostic
def test_a_week_of_ff_makes_the_year_a_model_year() -> None:
    decoded = decode_edid(edid_block(week=0xFF, year=2019))
    assert (decoded["week"], decoded["year"], decoded["model_year"]) == (None, 2019, True)


@pytest.mark.os_agnostic
def test_an_unspecified_text_descriptor_is_kept_as_text() -> None:
    assert decode_edid(edid_block(texts={0xFE: "PANEL-A"}))["text"] == "PANEL-A"


@pytest.mark.os_agnostic
def test_a_wrong_checksum_is_reported_not_refused() -> None:
    data = bytearray(edid_block())
    data[127] ^= 0xFF
    assert decode_edid(bytes(data))["checksum_ok"] is False


@pytest.mark.os_agnostic
def test_extension_blocks_after_the_base_block_do_not_change_it() -> None:
    assert decode_edid(edid_block(extensions=1) + bytes(128))["manufacturer"] == "VMW"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("data", [b"", bytes(128), edid_block()[:127]])
def test_bytes_that_are_not_an_edid_block_are_refused(data: bytes) -> None:
    with pytest.raises(ValueError, match="EDID"):
        decode_edid(data)
