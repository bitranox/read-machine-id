"""The pure PCI configuration space decoder, fed images built from the documented layout."""

from __future__ import annotations

import pytest
from pci_bytes import CAP_EXP, CAP_MSI, CAP_MSIX, CAP_PM, DSN_TEXT, DSN_VALUE, Config, endpoint_config, root_port_config

from fingerprint_machine.domain.pci_config import (
    PciePortType,
    decode_capabilities,
    decode_header,
    device_serial_number,
    serial_number_text,
    walk_capabilities,
)


@pytest.mark.os_agnostic
def test_the_header_of_an_endpoint_names_its_ids_class_and_interrupt_pin() -> None:
    header = decode_header(endpoint_config().bytes(64))
    assert header == {
        "vendor_id": "0x15ad",
        "device_id": "0x07c0",
        "command": "0x0407",
        "status": "0x0010",
        "revision": "0x02",
        "class_code": "0x010700",
        "header_type": 0,
        "multifunction": False,
        "interrupt_line": 11,
        "interrupt_pin": "INTA",
        "capabilities_pointer": "0x40",
        "subsystem_vendor_id": "0x15ad",
        "subsystem_id": "0x07c0",
    }


@pytest.mark.os_agnostic
def test_the_header_of_a_bridge_names_its_bus_numbers() -> None:
    header = decode_header(root_port_config().bytes(64))
    assert (header["header_type"], header["multifunction"], header["interrupt_pin"]) == (1, True, None)
    assert (header["primary_bus"], header["secondary_bus"], header["subordinate_bus"]) == (0, 3, 5)
    assert "subsystem_id" not in header


@pytest.mark.os_agnostic
def test_a_header_shorter_than_64_bytes_is_refused() -> None:
    with pytest.raises(ValueError, match="64 bytes"):
        decode_header(bytes(63))


@pytest.mark.os_agnostic
def test_the_walk_lists_every_capability_and_extended_capability_by_offset() -> None:
    walk = walk_capabilities(endpoint_config().bytes())
    assert [(c.cap_id, c.offset) for c in walk.capabilities] == [
        (CAP_PM, 0x40),
        (CAP_MSI, 0x48),
        (CAP_EXP, 0x60),
        (CAP_MSIX, 0x9C),
    ]
    assert [(c.cap_id, c.offset, c.version) for c in walk.extended] == [(1, 0x100, 2), (3, 0x140, 1), (0x10, 0x150, 1)]
    assert walk.unread_at is None


@pytest.mark.os_agnostic
def test_an_unprivileged_64_byte_read_stops_the_walk_at_the_first_pointer() -> None:
    walk = walk_capabilities(endpoint_config().bytes(64))
    assert (walk.capabilities, walk.extended, walk.unread_at) == ((), (), 0x40)


@pytest.mark.os_agnostic
def test_a_256_byte_space_has_no_extended_capabilities() -> None:
    walk = walk_capabilities(endpoint_config().bytes(256))
    assert len(walk.capabilities) == 4
    assert (walk.extended, walk.unread_at) == ((), None)


@pytest.mark.os_agnostic
def test_a_device_without_a_capability_list_walks_to_nothing() -> None:
    cfg = Config(64).put(0x06, "H", 0x0000).put(0x34, "B", 0x40)
    assert walk_capabilities(cfg.bytes()).unread_at is None


@pytest.mark.os_agnostic
def test_a_looping_capability_list_ends_instead_of_hanging() -> None:
    cfg = Config(256).put(0x06, "H", 0x0010).put(0x34, "B", 0x40).cap(0x40, CAP_PM, 0x50).cap(0x50, CAP_MSI, 0x40)
    walk = walk_capabilities(cfg.bytes())
    assert [c.offset for c in walk.capabilities] == [0x40, 0x50]


@pytest.mark.os_agnostic
def test_a_looping_extended_list_ends_instead_of_hanging() -> None:
    cfg = Config(4096).put(0x06, "H", 0x0000).ext(0x100, 0x01, 0x140).ext(0x140, 0x03, 0x100)
    assert [c.offset for c in walk_capabilities(cfg.bytes()).extended] == [0x100, 0x140]


@pytest.mark.os_agnostic
def test_the_decoded_capabilities_carry_dsn_pcie_msi_msix_aer_and_sriov() -> None:
    cfg = endpoint_config().bytes()
    decoded = decode_capabilities(cfg, walk_capabilities(cfg))
    assert decoded["list"] == [
        {"id": "0x01", "name": "power_management", "offset": "0x40"},
        {"id": "0x05", "name": "msi", "offset": "0x48"},
        {"id": "0x10", "name": "pci_express", "offset": "0x60"},
        {"id": "0x11", "name": "msi_x", "offset": "0x9c"},
    ]
    assert decoded["extended"] == [
        {"id": "0x0001", "name": "advanced_error_reporting", "offset": "0x100", "version": 2},
        {"id": "0x0003", "name": "device_serial_number", "offset": "0x140", "version": 1},
        {"id": "0x0010", "name": "sr_iov", "offset": "0x150", "version": 1},
    ]
    assert decoded["device_serial_number"] == DSN_TEXT
    assert decoded["pci_express"] == {
        "version": 2,
        "port_type": "endpoint",
        "slot_implemented": False,
        "physical_slot": None,
        "max_link_speed": 3,
        "max_link_width": 8,
    }
    assert decoded["msi"] == {
        "enabled": True,
        "vectors_capable": 8,
        "vectors_enabled": 2,
        "address_64bit": True,
        "per_vector_masking": False,
    }
    assert decoded["msi_x"] == {
        "enabled": True,
        "function_mask": False,
        "table_size": 32,
        "table_bar": 1,
        "table_offset": "0x2000",
        "pba_bar": 1,
        "pba_offset": "0x3000",
    }
    assert decoded["advanced_error_reporting"] == {
        "uncorrectable_status": "0x00000000",
        "uncorrectable_mask": "0x00400000",
        "uncorrectable_severity": "0x00062030",
        "correctable_status": "0x00000000",
        "correctable_mask": "0x00002000",
        "capabilities_control": "0x00000000",
    }
    assert decoded["sr_iov"] == {
        "vf_enabled": True,
        "initial_vfs": 8,
        "total_vfs": 16,
        "num_vfs": 4,
        "first_vf_offset": 0x80,
        "vf_stride": 2,
        "vf_device_id": "0x07c1",
    }


@pytest.mark.os_agnostic
def test_a_root_port_reports_its_port_type_and_slot() -> None:
    cfg = root_port_config().bytes()
    decoded = decode_capabilities(cfg, walk_capabilities(cfg))
    pcie = decoded["pci_express"]
    assert isinstance(pcie, dict)
    assert (pcie["port_type"], pcie["slot_implemented"], pcie["physical_slot"]) == ("root_port", True, 7)
    assert (decoded["device_serial_number"], decoded["msi"], decoded["msi_x"], decoded["sr_iov"]) == (
        None,
        None,
        None,
        None,
    )


@pytest.mark.os_agnostic
def test_an_unknown_capability_keeps_its_id_without_a_name() -> None:
    cfg = Config(256).put(0x06, "H", 0x0010).put(0x34, "B", 0x40).cap(0x40, 0x3F, 0x00).bytes()
    assert decode_capabilities(cfg, walk_capabilities(cfg))["list"] == [{"id": "0x3f", "name": None, "offset": "0x40"}]


@pytest.mark.os_agnostic
def test_an_unknown_port_type_is_kept_as_its_number() -> None:
    cfg = Config(256).put(0x06, "H", 0x0010).put(0x34, "B", 0x40).cap(0x40, CAP_EXP, 0x00).put(0x42, "H", 0x00B2)
    pcie = decode_capabilities(cfg.bytes(), walk_capabilities(cfg.bytes()))["pci_express"]
    assert isinstance(pcie, dict)
    assert pcie["port_type"] == "unknown(11)"


@pytest.mark.os_agnostic
def test_port_types_are_named_as_the_pcie_specification_numbers_them() -> None:
    assert PciePortType.from_number(4) is PciePortType.ROOT_PORT
    assert PciePortType.from_number(6) is PciePortType.DOWNSTREAM_PORT
    assert PciePortType.from_number(11) is None


@pytest.mark.os_agnostic
def test_the_device_serial_number_is_a_number_and_its_text_is_the_lspci_form() -> None:
    assert device_serial_number(endpoint_config().bytes()) == DSN_VALUE
    assert device_serial_number(root_port_config().bytes()) is None
    assert serial_number_text(DSN_VALUE) == DSN_TEXT
