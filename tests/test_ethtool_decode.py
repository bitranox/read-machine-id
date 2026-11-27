"""The ethtool ioctl structures built and decoded from hand-built bytes (``include/uapi/linux/ethtool.h``)."""

from __future__ import annotations

import struct

import pytest

from fingerprint_machine.domain.ethtool import (
    CHANNELS,
    COALESCE,
    PAUSE,
    RINGS,
    StringSet,
    decode_driver_info,
    decode_features,
    decode_link_settings,
    decode_permanent_address,
    decode_string_count,
    decode_strings,
    decode_wake_on_lan,
    driver_info_request,
    features_request,
    link_settings_request,
    link_settings_words,
    permanent_address_request,
    string_count_request,
    strings_request,
    wake_on_lan_request,
)


def _text(value: bytes, size: int) -> bytes:
    return value.ljust(size, b"\0")


@pytest.mark.os_agnostic
def test_driver_info_reads_the_four_names() -> None:
    assert driver_info_request()[:4] == struct.pack("<I", 0x03)
    assert len(driver_info_request()) == 196
    answer = struct.pack(
        "<I32s32s32s32s32s12sIIIII",
        0x03, _text(b"vmxnet3", 32), _text(b"1.9.0.0-k", 32), _text(b"", 32), _text(b"0000:0b:00.0", 32),
        _text(b"", 32), bytes(12), 0, 30, 0, 0, 1024,
    )  # fmt: skip
    assert decode_driver_info(answer) == {
        "driver": "vmxnet3",
        "version": "1.9.0.0-k",
        "firmware_version": "",
        "bus_info": "0000:0b:00.0",
        "expansion_rom_version": "",
        "priv_flags": 0,
        "stats": 30,
        "test_info_length": 0,
        "eeprom_dump_length": 0,
        "register_dump_length": 1024,
    }


@pytest.mark.os_agnostic
def test_the_permanent_address_is_as_long_as_the_kernel_says() -> None:
    request = permanent_address_request()
    assert struct.unpack_from("<II", request) == (0x20, 32)
    answer = struct.pack("<II", 0x20, 6) + bytes.fromhex("005056000001") + bytes(26)
    assert decode_permanent_address(answer) == "00:50:56:00:00:01"


@pytest.mark.os_agnostic
def test_a_string_set_the_device_does_not_have_is_refused() -> None:
    assert string_count_request(StringSet.FEATURES) == struct.pack("<IIQI", 0x37, 0, 1 << 4, 0)
    assert decode_string_count(struct.pack("<IIQI", 0x37, 0, 1 << 4, 3)) == 3
    with pytest.raises(ValueError, match="not offered"):
        decode_string_count(struct.pack("<IIQI", 0x37, 0, 0, 0))


@pytest.mark.os_agnostic
def test_strings_are_32_byte_names() -> None:
    assert strings_request(StringSet.FEATURES, 2) == struct.pack("<III", 0x1B, 4, 2) + bytes(64)
    answer = struct.pack("<III", 0x1B, 4, 2) + _text(b"rx-checksum", 32) + _text(b"tx-checksum-ipv4", 32)
    assert decode_strings(answer) == ["rx-checksum", "tx-checksum-ipv4"]


@pytest.mark.os_agnostic
def test_each_feature_is_on_or_off_and_fixed_when_it_cannot_change() -> None:
    names = [f"f{i}" for i in range(34)]
    assert features_request(len(names)) == struct.pack("<II", 0x3A, 2) + bytes(32)
    # Block 0: f0 available+requested+active; f1 not available (fixed off); f2 active but never changed.
    block0 = struct.pack("<IIII", 0b001, 0b001, 0b101, 0b100)
    block1 = struct.pack("<IIII", 0b10, 0b10, 0b10, 0)  # f33 on and changeable
    features = decode_features(struct.pack("<II", 0x3A, 2) + block0 + block1, names)
    assert features["f0"] == {"active": True, "requested": True, "fixed": False}
    assert features["f1"] == {"active": False, "requested": False, "fixed": True}
    assert features["f2"] == {"active": True, "requested": False, "fixed": True}
    assert features["f33"] == {"active": True, "requested": True, "fixed": False}
    assert len(features) == 34


@pytest.mark.os_agnostic
def test_rings_channels_coalesce_and_pause_are_named_u32_fields() -> None:
    assert RINGS.request() == struct.pack("<I", 0x10) + bytes(32)
    rings = RINGS.decode(struct.pack("<9I", 0x10, 4096, 0, 0, 4096, 1024, 0, 0, 512))
    assert (rings["rx_max_pending"], rings["tx_pending"]) == (4096, 512)
    channels = CHANNELS.decode(struct.pack("<9I", 0x3C, 0, 0, 0, 8, 0, 0, 0, 4))
    assert (channels["max_combined"], channels["combined_count"]) == (8, 4)
    coalesce = COALESCE.decode(struct.pack("<23I", 0x0E, 50, *range(21)))
    assert (len(coalesce), coalesce["rx_coalesce_usecs"], coalesce["rate_sample_interval"]) == (22, 50, 20)
    assert PAUSE.decode(struct.pack("<4I", 0x12, 1, 0, 1)) == {"autoneg": 1, "rx_pause": 0, "tx_pause": 1}


@pytest.mark.os_agnostic
def test_wake_on_lan_names_the_modes_and_never_the_secureon_password() -> None:
    assert wake_on_lan_request() == struct.pack("<III", 0x05, 0, 0) + bytes(8)
    answer = struct.pack("<III", 0x05, 0x21, 0x20) + b"SECRET" + bytes(2)
    wol = decode_wake_on_lan(answer)
    assert wol == {"supported": ["phy", "magic"], "enabled": ["magic"]}
    assert "SECRET" not in repr(wol)


@pytest.mark.os_agnostic
def test_link_settings_take_a_size_handshake_then_name_the_modes() -> None:
    assert link_settings_request(0) == struct.pack("<I", 0x4C) + bytes(44)
    probe = bytearray(48)
    struct.pack_into("<I", probe, 0, 0x4C)
    struct.pack_into("<b", probe, 15, -2)
    assert link_settings_words(bytes(probe)) == 2
    request = link_settings_request(2)
    assert len(request) == 48 + 3 * 2 * 4 and struct.unpack_from("<b", request, 15) == (2,)
    head = struct.pack("<IIBBBBBBBbBBBB", 0x4C, 10000, 1, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0) + bytes(28)
    masks = struct.pack("<6I", 0b011, 1 << 1, 0b001, 1 << 1, 0b010, 0)
    names = [f"mode{i}" for i in range(64)]
    settings = decode_link_settings(head + masks, names)
    assert settings == {
        "speed_mbps": 10000,
        "duplex": "full",
        "port": "twisted_pair",
        "autoneg": True,
        "supported": ["mode0", "mode1", "mode33"],
        "advertising": ["mode0", "mode33"],
        "link_partner_advertising": ["mode1"],
    }


@pytest.mark.os_agnostic
def test_an_unknown_speed_and_duplex_read_as_none_and_unknown() -> None:
    head = struct.pack("<IIBBBBBBBbBBBB", 0x4C, 0xFFFFFFFF, 0xFF, 0xEF, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0) + bytes(28)
    settings = decode_link_settings(head + bytes(12), [])
    assert (settings["speed_mbps"], settings["duplex"], settings["port"]) == (None, "unknown", "none")


@pytest.mark.os_agnostic
def test_a_short_answer_is_refused() -> None:
    with pytest.raises(ValueError, match="bytes"):
        decode_driver_info(b"\x03\x00\x00\x00")


@pytest.mark.os_agnostic
def test_an_unnamed_feature_slot_is_skipped() -> None:
    block = struct.pack("<IIII", 0b11, 0b11, 0b11, 0)
    assert list(decode_features(struct.pack("<II", 0x3A, 1) + block, ["rx-gro", ""])) == ["rx-gro"]
