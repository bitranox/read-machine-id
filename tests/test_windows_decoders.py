"""The decoders the Windows readers use: PCI ids and locations, WMI object paths, device properties,
INQUIRY answers and NUMA nodes. Every value is invented."""

from __future__ import annotations

import uuid

import pytest

from fingerprint_machine.domain.devprops import PCI_PROPERTIES, DeviceProperty, decode_property
from fingerprint_machine.domain.numa import NumaNode
from fingerprint_machine.domain.scsi_inquiry import decode_inquiry
from fingerprint_machine.domain.windows_pci import (
    InterruptSupport,
    parse_wmi_reference,
    pci_ids,
    pci_location,
    pci_location_from_address,
    unique_id_serial,
)


@pytest.mark.os_agnostic
def test_ids_missing_from_the_hardware_ids_read_as_none() -> None:
    ids = pci_ids([r"PCI\VEN_8086&DEV_2938", 7, None])
    assert ids.as_json() == {
        "vendor_id": "0x8086",
        "device_id": "0x2938",
        "subsystem_vendor_id": None,
        "subsystem_id": None,
        "revision": None,
        "class_code": None,
    }


@pytest.mark.os_agnostic
def test_the_subsystem_id_comes_before_its_vendor_in_subsys() -> None:
    ids = pci_ids([r"PCI\VEN_1AF4&DEV_1041&SUBSYS_11001AF4&REV_01"])
    assert (ids.subsystem_id, ids.subsystem_vendor_id) == ("0x1100", "0x1af4")


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("text", "address"),
    [
        ("@System32\\drivers\\pci.sys,#65536;PCI bus %1, device %2, function %3;(0,31,6)", "0000:00:1f.6"),
        ("PCI bus 255, device 31, function 7", "0000:ff:1f.7"),
        ("Bus PCI 4, dispositivo 2, funzione 1", "0000:04:02.1"),
    ],
)
def test_a_location_names_bus_device_and_function_in_any_language(text: str, address: str) -> None:
    location = pci_location(text)
    assert location is not None
    assert location.address == address


@pytest.mark.os_agnostic
@pytest.mark.parametrize("text", [None, 17, "", "PCI Slot 3", "\u00e9\u4e2d\U0001f600"])
def test_a_location_without_three_numbers_names_none(text: object) -> None:
    assert pci_location(text) is None


@pytest.mark.os_agnostic
def test_the_device_address_property_splits_into_device_and_function() -> None:
    assert pci_location_from_address(bus=0, address=(0x1C << 16) | 4).as_json() == {
        "bus": 0,
        "device": 0x1C,
        "function": 4,
    }


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("instance", "capabilities"),
    [
        (r"PCI\VEN_1\0123ABCD5005056000", 0x4),
        (r"PCI\VEN_1\3&11583659&0&D1", 0x10),
        (r"PCI\VEN_1\0123ABCD50050560", 0x10),
        (r"PCI\VEN_1\0123ABCD5005056000", "16"),
        (None, 0x10),
    ],
)
def test_only_a_unique_instance_id_of_serial_shape_gives_a_serial(instance: object, capabilities: object) -> None:
    assert unique_id_serial(instance, capabilities) is None


@pytest.mark.os_agnostic
def test_interrupt_support_names_each_kind_and_refuses_non_numbers() -> None:
    assert InterruptSupport.names(7) == ["line_based", "msi", "msi_x"]
    assert InterruptSupport.names(0) == []
    assert InterruptSupport.names(True) is None
    assert InterruptSupport.names("5") is None


@pytest.mark.os_agnostic
def test_a_wmi_path_with_several_keys_and_escaped_quotes_is_read_whole() -> None:
    ref = parse_wmi_reference(r'Win32_X.A="say \"hi\"",B=5')
    assert ref.class_name == "Win32_X"
    assert (ref.key("a"), ref.key("B"), ref.key("C")) == ('say "hi"', "5", None)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("text", ["", "not an object path", r"\\H\root\cimv2:Win32_X.", "Win32_X.=5"])
def test_text_that_is_no_wmi_path_is_refused(text: str) -> None:
    with pytest.raises(ValueError, match="WMI object path"):
        parse_wmi_reference(text)


@pytest.mark.os_agnostic
def test_device_property_values_decode_by_their_type() -> None:
    guid = uuid.UUID("4340a6c5-93fa-4706-972c-7b648008a5a7")
    assert decode_property(0x0D, guid.bytes_le) == str(guid)
    assert decode_property(0x06, (-2).to_bytes(4, "little", signed=True)) == -2
    assert decode_property(0x11, b"\x00") is False
    assert decode_property(0x12, b"") == ""
    assert decode_property(0x2012, "\u4e2d\U0001f600\0\0".encode("utf-16-le")) == ["\u4e2d\U0001f600"]
    assert decode_property(0x1003, b"\x01\x02") == "0102"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("code", "raw"), [(0x07, b"\x01\x02"), (0x09, bytes(7)), (0x0D, bytes(15))])
def test_a_property_shorter_than_its_type_is_refused(code: int, raw: bytes) -> None:
    with pytest.raises(ValueError, match="bytes"):
        decode_property(code, raw)


@pytest.mark.os_agnostic
def test_every_pci_property_has_a_key_in_the_pci_property_set() -> None:
    assert len(PCI_PROPERTIES) == 16
    assert {p.key.pid for p in PCI_PROPERTIES} == set(range(1, 17))
    assert DeviceProperty.LOCATION_PATHS.key.pid == 37


@pytest.mark.os_agnostic
def test_an_inquiry_answer_decodes_its_qualifier_and_removable_bit() -> None:
    answer = bytes([0x65, 0x80, 5, 2, 31, 0, 0, 0]) + b"ACME    DVD drive       1.00"
    inquiry = decode_inquiry(answer)
    assert (inquiry.type, inquiry.qualifier, inquiry.removable, inquiry.version) == (5, 3, True, 5)
    assert (inquiry.vendor, inquiry.model, inquiry.rev) == ("ACME", "DVD drive", "1.00")


@pytest.mark.os_agnostic
def test_an_inquiry_answer_too_short_for_its_identity_is_refused() -> None:
    with pytest.raises(ValueError, match="36 bytes"):
        decode_inquiry(bytes(35))


@pytest.mark.os_agnostic
def test_a_numa_node_lists_its_processors_within_its_group() -> None:
    node = NumaNode(node=1, group=1, mask=1 << 63 | 1).as_json()
    assert node == {"node": 1, "processor_group": 1, "processor_mask": "0x8000000000000001", "processors": [0, 63]}
