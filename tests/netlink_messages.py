"""Build rtnetlink messages by hand, from the layouts in ``include/uapi/linux``.

Used by the decoder tests and by the synthetic Linux machines, which record a netlink dump as the
messages a kernel would send.

Contents:
    * :func:`attr` - one ``struct rtattr``, padded.
    * :func:`message` - one ``struct nlmsghdr`` around a body.
    * :func:`link`, :func:`address`, :func:`route`, :func:`neighbour` - one message of each dump.
    * :func:`done`, :func:`error` - the messages that end a dump.
"""

from __future__ import annotations

import ipaddress
import struct

_RTM_NEWLINK = 16
_RTM_NEWADDR = 20
_RTM_NEWROUTE = 24
_RTM_NEWNEIGH = 28
_NLM_F_MULTI = 0x02


def attr(kind: int, value: bytes) -> bytes:
    """Return one attribute: length, type, value, padded to 4 bytes."""
    length = 4 + len(value)
    return struct.pack("<HH", length, kind) + value + bytes((4 - length % 4) % 4)


def message(kind: int, body: bytes, *, sequence: int = 1) -> bytes:
    """Return one netlink message (header + body)."""
    return struct.pack("<IHHII", 16 + len(body), kind, _NLM_F_MULTI, sequence, 0) + body


def _text(value: str) -> bytes:
    return value.encode() + b"\0"


def link(*, index: int, name: str, mac: str, mtu: int = 1500, kind: str | None = None, flags: int = 0x11043) -> bytes:
    """Return an ``RTM_NEWLINK`` for an Ethernet interface."""
    attrs = attr(3, _text(name)) + attr(1, bytes.fromhex(mac.replace(":", ""))) + attr(4, struct.pack("<I", mtu))
    attrs += attr(54, bytes.fromhex(mac.replace(":", ""))) + attr(16, bytes([6])) + attr(31, struct.pack("<I", 2))
    if kind is not None:
        attrs += attr(18, attr(1, _text(kind)))
    return message(_RTM_NEWLINK, struct.pack("<BxHiII", 0, 1, index, flags, 0) + attrs)


def address(*, index: int, ip: str, prefix: int, label: str) -> bytes:
    """Return an ``RTM_NEWADDR`` for one address of an interface."""
    parsed = ipaddress.ip_address(ip)
    family = 2 if parsed.version == 4 else 10
    attrs = attr(1, parsed.packed) + attr(2, parsed.packed) + attr(3, _text(label)) + attr(8, struct.pack("<I", 0x80))
    return message(_RTM_NEWADDR, struct.pack("<BBBBI", family, prefix, 0x80, 0, index) + attrs)


def route(*, destination: str | None, gateway: str | None, out_index: int, prefix: int = 0) -> bytes:
    """Return an ``RTM_NEWROUTE`` in the main table (IPv4)."""
    attrs = attr(15, struct.pack("<I", 254)) + attr(4, struct.pack("<I", out_index))
    if destination is not None:
        attrs += attr(1, ipaddress.ip_address(destination).packed)
    if gateway is not None:
        attrs += attr(5, ipaddress.ip_address(gateway).packed)
    return message(_RTM_NEWROUTE, struct.pack("<BBBBBBBBI", 2, prefix, 0, 0, 254, 4, 0, 1, 0) + attrs)


def neighbour(*, index: int, ip: str, mac: str) -> bytes:
    """Return an ``RTM_NEWNEIGH`` in state reachable."""
    attrs = attr(1, ipaddress.ip_address(ip).packed) + attr(2, bytes.fromhex(mac.replace(":", "")))
    return message(_RTM_NEWNEIGH, struct.pack("<BxxxiHBB", 2, index, 0x02, 0, 1) + attrs)


def done() -> bytes:
    """Return the ``NLMSG_DONE`` that ends a dump."""
    return message(3, struct.pack("<i", 0))


def error(errno_value: int) -> bytes:
    """Return an ``NLMSG_ERROR`` carrying ``-errno_value``."""
    return message(2, struct.pack("<i", -errno_value) + bytes(16))


__all__ = ["address", "attr", "done", "error", "link", "message", "neighbour", "route"]
