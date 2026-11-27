"""rtnetlink dump messages decoded from hand-built bytes (``include/uapi/linux/rtnetlink.h``)."""

from __future__ import annotations

import struct

import pytest
from netlink_messages import address, attr, done, error, link, message, neighbour, route

from fingerprint_machine.domain.netlink import (
    DumpKind,
    decode_address,
    decode_link,
    decode_neighbour,
    decode_route,
    dump_request,
    error_number,
    hardware_type,
    interface_flags,
    is_done,
    split_messages,
)


@pytest.mark.os_agnostic
def test_a_dump_request_asks_for_every_entry() -> None:
    request = dump_request(DumpKind.ROUTES, sequence=7)
    length, kind, flags, sequence, _ = struct.unpack_from("<IHHII", request)
    assert (length, kind, flags, sequence, len(request)) == (28, 26, 0x301, 7, 28)


@pytest.mark.os_agnostic
def test_a_buffer_splits_into_its_messages_and_the_last_ends_the_dump() -> None:
    first = link(index=2, name="eth0", mac="00:50:56:00:00:01")
    buffer = first + done()
    messages = list(split_messages(buffer))
    assert messages[0] == first
    assert [is_done(m) for m in messages] == [False, True]
    assert error_number(messages[0]) is None


@pytest.mark.os_agnostic
def test_an_error_message_carries_its_errno() -> None:
    assert error_number(error(1)) == 1


@pytest.mark.os_agnostic
def test_a_message_longer_than_the_buffer_is_refused() -> None:
    with pytest.raises(ValueError, match="states"):
        list(split_messages(link(index=2, name="eth0", mac="00:50:56:00:00:01")[:-4]))


@pytest.mark.os_agnostic
def test_a_link_names_its_addresses_queues_and_kind() -> None:
    decoded = decode_link(link(index=2, name="eth0", mac="00:50:56:00:00:01", mtu=9000, kind="veth"))
    assert decoded == {
        "index": 2,
        "type": "ether",
        "flags": ["up", "broadcast", "running", "multicast", "lower_up"],
        "name": "eth0",
        "address": "00:50:56:00:00:01",
        "permanent_address": "00:50:56:00:00:01",
        "mtu": 9000,
        "num_tx_queues": 2,
        "operstate": "up",
        "kind": "veth",
    }


@pytest.mark.os_agnostic
def test_a_link_lists_every_alternative_name() -> None:
    props = attr(53, b"enp11s0\0") + attr(53, b"enx005056000001\0")
    body = struct.pack("<BxHiII", 0, 1, 3, 0, 0) + attr(3, b"eth1\0") + attr(0x8000 | 52, props)
    assert decode_link(message(16, body))["alt_names"] == ["enp11s0", "enx005056000001"]


@pytest.mark.os_agnostic
def test_addresses_routes_and_neighbours_decode() -> None:
    assert decode_address(address(index=2, ip="192.0.2.10", prefix=24, label="eth0")) == {
        "index": 2,
        "family": "ipv4",
        "prefix_length": 24,
        "scope": "universe",
        "flags": ["permanent"],
        "address": "192.0.2.10",
        "local": "192.0.2.10",
        "label": "eth0",
    }
    default = decode_route(route(destination=None, gateway="192.0.2.1", out_index=2))
    assert (default["destination"], default["gateway"], default["table"], default["protocol"]) == (
        "0.0.0.0/0",
        "192.0.2.1",
        "main",
        "static",
    )
    assert (default["type"], default["output_index"]) == ("unicast", 2)
    assert decode_neighbour(neighbour(index=2, ip="192.0.2.1", mac="02:00:00:00:00:fe")) == {
        "index": 2,
        "family": "ipv4",
        "address": "192.0.2.1",
        "link_address": "02:00:00:00:00:fe",
        "state": ["reachable"],
    }


@pytest.mark.os_agnostic
def test_ipv6_addresses_and_prefix_routes_print_as_text() -> None:
    assert decode_address(address(index=2, ip="2001:db8::10", prefix=64, label="eth0"))["address"] == "2001:db8::10"
    assert decode_route(route(destination="198.51.100.0", gateway=None, out_index=2, prefix=24))["destination"] == (
        "198.51.100.0/24"
    )


@pytest.mark.os_agnostic
def test_flags_and_hardware_types_keep_unnamed_numbers() -> None:
    assert interface_flags(0x8 | 1 << 25) == ["loopback", "bit25"]
    assert (hardware_type(772), hardware_type(4242)) == ("loopback", "4242")


@pytest.mark.os_agnostic
def test_a_cut_message_is_refused() -> None:
    with pytest.raises(ValueError, match="shorter"):
        decode_link(message(16, b"\x00\x00"))


@pytest.mark.os_agnostic
def test_bytes_shorter_than_a_header_are_refused_not_crashed_on() -> None:
    with pytest.raises(ValueError, match="header"):
        error_number(b"\x10\x00")
    with pytest.raises(ValueError, match="error code"):
        error_number(message(2, b""))
