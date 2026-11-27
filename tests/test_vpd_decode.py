"""SCSI VPD pages 0x80 and 0x83 decoded from hand-built bytes (SPC-5 sections 7.7.3 and 7.7.18)."""

from __future__ import annotations

import pytest

from fingerprint_machine.domain.vpd import decode_vpd_page80, decode_vpd_page83


def _page(code: int, body: bytes) -> bytes:
    # Byte 0 peripheral qualifier/type (0 = disk), byte 1 page code, bytes 2-3 page length (BE).
    return bytes([0, code]) + len(body).to_bytes(2, "big") + body


def _designator(
    *, code_set: int, association: int, kind: int, value: bytes, protocol: int = 0, piv: bool = False
) -> bytes:
    byte1 = (0x80 if piv else 0) | (association << 4) | kind
    return bytes([(protocol << 4) | code_set, byte1, 0, len(value)]) + value


@pytest.mark.os_agnostic
def test_page80_is_the_unit_serial_without_padding() -> None:
    assert decode_vpd_page80(_page(0x80, b"SER-0001    ")) == "SER-0001"


@pytest.mark.os_agnostic
def test_page80_refuses_another_page() -> None:
    with pytest.raises(ValueError, match="page 0x83"):
        decode_vpd_page80(_page(0x83, b"SER-0001"))


@pytest.mark.os_agnostic
def test_page83_names_each_designator() -> None:
    naa = _designator(code_set=1, association=0, kind=3, value=bytes.fromhex("6000c29aaaaaaaaa"))
    t10 = _designator(code_set=2, association=0, kind=1, value=b"ATA     Example Disk SER-0001")
    port = _designator(code_set=1, association=1, kind=3, value=bytes.fromhex("5000c29bbbbbbbbb"), protocol=6, piv=True)
    designators = decode_vpd_page83(_page(0x83, naa + t10 + port))
    assert [d.as_json() for d in designators] == [
        {"type": "naa", "association": "logical_unit", "code_set": "binary", "protocol": None,
         "value": "6000c29aaaaaaaaa"},
        {"type": "t10_vendor_id", "association": "logical_unit", "code_set": "ascii", "protocol": None,
         "value": "ATA     Example Disk SER-0001"},
        {"type": "naa", "association": "target_port", "code_set": "binary", "protocol": "sas",
         "value": "5000c29bbbbbbbbb"},
    ]  # fmt: skip


@pytest.mark.os_agnostic
def test_page83_keeps_an_unknown_designator_type_by_number() -> None:
    odd = _designator(code_set=1, association=0, kind=0xE, value=b"\x01\x02")
    (designator,) = decode_vpd_page83(_page(0x83, odd))
    assert (designator.as_json()["type"], designator.as_json()["value"]) == ("type14", "0102")


@pytest.mark.os_agnostic
def test_page83_refuses_a_designator_that_runs_past_the_page() -> None:
    cut = _designator(code_set=1, association=0, kind=3, value=bytes(8))[:-2]
    with pytest.raises(ValueError, match="runs past"):
        decode_vpd_page83(_page(0x83, cut))


@pytest.mark.os_agnostic
def test_a_page_shorter_than_its_header_is_refused() -> None:
    with pytest.raises(ValueError, match="header"):
        decode_vpd_page83(b"\x00\x83")
