"""The ethtool ioctl structures: the request bytes for each question and the decoding of the answer.

Linux answers ``SIOCETHTOOL`` with a C structure the caller allocated: the request is the whole
structure with its command first, and the kernel fills it in place. Each layout here follows
``include/uapi/linux/ethtool.h``. Names the kernel keeps in a string set (the offload features,
the link modes) are asked from the kernel rather than copied into this file, so a newer kernel's
new feature is named without a change here.

Contents:
    * :class:`StringSet` - the kernel string sets read.
    * :class:`U32Fields` - a structure that is a command followed by named ``u32`` fields.
    * :data:`RINGS`, :data:`CHANNELS`, :data:`COALESCE`, :data:`PAUSE` - such structures.
    * :class:`FeatureState`, :class:`Duplex`, :class:`Port` - decoded categorical values.
    * ``*_request`` / ``decode_*`` - one pair per question.
    * :func:`link_settings_words` - the size handshake of ``ETHTOOL_GLINKSETTINGS``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .json_types import JsonObject, JsonValue


class _Command(IntEnum):
    """The ``ETHTOOL_*`` commands asked."""

    GDRVINFO = 0x03
    GWOL = 0x05
    GCOALESCE = 0x0E
    GRINGPARAM = 0x10
    GPAUSEPARAM = 0x12
    GSTRINGS = 0x1B
    GPERMADDR = 0x20
    GSSET_INFO = 0x37
    GFEATURES = 0x3A
    GCHANNELS = 0x3C
    GLINKSETTINGS = 0x4C


class StringSet(IntEnum):
    """``enum ethtool_stringset``: the kernel name tables read."""

    FEATURES = 4
    LINK_MODES = 9


class Duplex(StrEnum):
    """The link duplex (``DUPLEX_*``)."""

    HALF = "half"
    FULL = "full"
    UNKNOWN = "unknown"


class Port(StrEnum):
    """The physical connector (``PORT_*``)."""

    TWISTED_PAIR = "twisted_pair"
    AUI = "aui"
    BNC = "bnc"
    MII = "mii"
    FIBRE = "fibre"
    DIRECT_ATTACH = "direct_attach"
    NONE = "none"
    OTHER = "other"


_GSTRING_LEN = 32
_MAX_ADDR_LEN = 32
_U32 = struct.Struct("<I")
_DRVINFO = struct.Struct("<I32s32s32s32s32s12sIIIII")
_PERM_ADDR = struct.Struct("<II")
_SSET_INFO = struct.Struct("<IIQI")
_GSTRINGS = struct.Struct("<III")
_GFEATURES = struct.Struct("<II")
_FEATURE_BLOCK = struct.Struct("<IIII")
_WOL = struct.Struct("<III6s2x")
_LINK_SETTINGS = struct.Struct("<IIBBBBBBBbBBBB28x")
_NWORDS_OFFSET = 15
_SPEED_UNKNOWN = 0xFFFFFFFF
_DUPLEXES = {0: Duplex.HALF, 1: Duplex.FULL}
_PORTS = {
    0x00: Port.TWISTED_PAIR, 0x01: Port.AUI, 0x02: Port.BNC, 0x03: Port.MII,
    0x04: Port.FIBRE, 0x05: Port.DIRECT_ATTACH, 0xEF: Port.NONE, 0xFF: Port.OTHER,
}  # fmt: skip
# WAKE_* bits, in bit order (WAKE_PHY = 1 << 0 ... WAKE_FILTER = 1 << 7).
_WOL_MODES = ("phy", "unicast", "multicast", "broadcast", "arp", "magic", "magic_secure", "filter")


def _need(answer: bytes, size: int, what: str) -> None:
    if len(answer) < size:
        raise ValueError(f"{what}: {len(answer)} bytes, expected {size}")


def _name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _bits(words: Sequence[int], names: Sequence[str]) -> list[JsonValue]:
    """Return the name of every set bit, ``bit<N>`` where the table has none."""
    out: list[JsonValue] = []
    for index, word in enumerate(words):
        for bit in range(32):
            if word >> bit & 1:
                number = index * 32 + bit
                out.append(names[number] if number < len(names) and names[number] else f"bit{number}")
    return out


@dataclass(frozen=True, slots=True)
class U32Fields:
    """An ethtool structure that is a ``u32`` command followed by named ``u32`` fields."""

    command: int
    fields: tuple[str, ...]

    def request(self) -> bytes:
        """Return the zeroed structure with its command set."""
        return _U32.pack(self.command) + bytes(4 * len(self.fields))

    def decode(self, answer: bytes) -> JsonObject:
        """Return every field of an answer by name.

        Raises:
            ValueError: the answer is shorter than the structure.
        """
        layout = struct.Struct(f"<{1 + len(self.fields)}I")
        _need(answer, layout.size, f"ethtool 0x{self.command:02x}")
        return dict(zip(self.fields, layout.unpack_from(answer)[1:], strict=True))


#: ``struct ethtool_ringparam``.
RINGS = U32Fields(
    _Command.GRINGPARAM,
    (
        "rx_max_pending", "rx_mini_max_pending", "rx_jumbo_max_pending", "tx_max_pending",
        "rx_pending", "rx_mini_pending", "rx_jumbo_pending", "tx_pending",
    ),
)  # fmt: skip
#: ``struct ethtool_channels``.
CHANNELS = U32Fields(
    _Command.GCHANNELS,
    (
        "max_rx", "max_tx", "max_other", "max_combined",
        "rx_count", "tx_count", "other_count", "combined_count",
    ),
)  # fmt: skip
#: ``struct ethtool_coalesce``.
COALESCE = U32Fields(
    _Command.GCOALESCE,
    (
        "rx_coalesce_usecs", "rx_max_coalesced_frames", "rx_coalesce_usecs_irq", "rx_max_coalesced_frames_irq",
        "tx_coalesce_usecs", "tx_max_coalesced_frames", "tx_coalesce_usecs_irq", "tx_max_coalesced_frames_irq",
        "stats_block_coalesce_usecs", "use_adaptive_rx_coalesce", "use_adaptive_tx_coalesce", "pkt_rate_low",
        "rx_coalesce_usecs_low", "rx_max_coalesced_frames_low", "tx_coalesce_usecs_low",
        "tx_max_coalesced_frames_low", "pkt_rate_high", "rx_coalesce_usecs_high", "rx_max_coalesced_frames_high",
        "tx_coalesce_usecs_high", "tx_max_coalesced_frames_high", "rate_sample_interval",
    ),
)  # fmt: skip
#: ``struct ethtool_pauseparam``.
PAUSE = U32Fields(_Command.GPAUSEPARAM, ("autoneg", "rx_pause", "tx_pause"))


@dataclass(frozen=True, slots=True)
class FeatureState:
    """One offload feature: whether it is on, whether it was asked for, whether it can change."""

    active: bool
    requested: bool
    fixed: bool

    def as_json(self) -> JsonObject:
        """Return the state as a reading records it."""
        return {"active": self.active, "requested": self.requested, "fixed": self.fixed}


def driver_info_request() -> bytes:
    """Return the ``ETHTOOL_GDRVINFO`` request."""
    return _U32.pack(_Command.GDRVINFO) + bytes(_DRVINFO.size - _U32.size)


def decode_driver_info(answer: bytes) -> JsonObject:
    """Return the driver, its version, the firmware version and the bus address of a NIC.

    Raises:
        ValueError: the answer is shorter than ``struct ethtool_drvinfo``.
    """
    _need(answer, _DRVINFO.size, "ethtool drvinfo")
    _, driver, version, firmware, bus, erom, _, priv, stats, test, eeprom, regs = _DRVINFO.unpack_from(answer)
    return {
        "driver": _name(driver),
        "version": _name(version),
        "firmware_version": _name(firmware),
        "bus_info": _name(bus),
        "expansion_rom_version": _name(erom),
        "priv_flags": priv,
        "stats": stats,
        "test_info_length": test,
        "eeprom_dump_length": eeprom,
        "register_dump_length": regs,
    }


def permanent_address_request() -> bytes:
    """Return the ``ETHTOOL_GPERMADDR`` request, room for the longest hardware address."""
    return _PERM_ADDR.pack(_Command.GPERMADDR, _MAX_ADDR_LEN) + bytes(_MAX_ADDR_LEN)


def decode_permanent_address(answer: bytes) -> str:
    """Return the burned-in hardware address, colon separated.

    Raises:
        ValueError: the answer is shorter than the address length it states.
    """
    _need(answer, _PERM_ADDR.size, "ethtool permaddr")
    _, size = _PERM_ADDR.unpack_from(answer)
    _need(answer, _PERM_ADDR.size + size, "ethtool permaddr")
    return answer[_PERM_ADDR.size : _PERM_ADDR.size + size].hex(":")


def string_count_request(string_set: StringSet) -> bytes:
    """Return the ``ETHTOOL_GSSET_INFO`` request asking how many names a string set holds."""
    return _SSET_INFO.pack(_Command.GSSET_INFO, 0, 1 << string_set, 0)


def decode_string_count(answer: bytes) -> int:
    """Return the number of names in the string set asked.

    Raises:
        ValueError: the device does not offer the set, or the answer is short.
    """
    _need(answer, _SSET_INFO.size, "ethtool sset_info")
    _, _, mask, count = _SSET_INFO.unpack_from(answer)
    if not mask:
        raise ValueError("ethtool string set not offered by this device")
    return int(count)


def strings_request(string_set: StringSet, count: int) -> bytes:
    """Return the ``ETHTOOL_GSTRINGS`` request with room for ``count`` names."""
    return _GSTRINGS.pack(_Command.GSTRINGS, string_set, count) + bytes(count * _GSTRING_LEN)


def decode_strings(answer: bytes) -> list[str]:
    """Return the names of a string set, in kernel order.

    Raises:
        ValueError: the answer is shorter than the names it states.
    """
    _need(answer, _GSTRINGS.size, "ethtool gstrings")
    count = _GSTRINGS.unpack_from(answer)[2]
    _need(answer, _GSTRINGS.size + count * _GSTRING_LEN, "ethtool gstrings")
    start = _GSTRINGS.size
    return [_name(answer[start + i * _GSTRING_LEN : start + (i + 1) * _GSTRING_LEN]) for i in range(count)]


def _feature_blocks(count: int) -> int:
    return (count + 31) // 32


def features_request(count: int) -> bytes:
    """Return the ``ETHTOOL_GFEATURES`` request for ``count`` features."""
    blocks = _feature_blocks(count)
    return _GFEATURES.pack(_Command.GFEATURES, blocks) + bytes(blocks * _FEATURE_BLOCK.size)


def decode_features(answer: bytes, names: Sequence[str]) -> JsonObject:
    """Return every named feature's state, as ``ethtool -k`` shows it.

    A feature is fixed when the driver does not offer to change it or it may never change. A slot
    the kernel leaves unnamed is skipped, as ``ethtool -k`` skips it.

    Raises:
        ValueError: the answer is shorter than the features named.
    """
    blocks = _feature_blocks(len(names))
    _need(answer, _GFEATURES.size + blocks * _FEATURE_BLOCK.size, "ethtool gfeatures")
    out: JsonObject = {}
    for number, name in enumerate(names):
        if not name:  # a slot the kernel keeps unnamed (a retired feature)
            continue
        offset = _GFEATURES.size + (number // 32) * _FEATURE_BLOCK.size
        available, requested, active, never_changed = _FEATURE_BLOCK.unpack_from(answer, offset)
        bit = 1 << (number % 32)
        state = FeatureState(
            active=bool(active & bit),
            requested=bool(requested & bit),
            fixed=not available & bit or bool(never_changed & bit),
        )
        out[name] = state.as_json()
    return out


def wake_on_lan_request() -> bytes:
    """Return the ``ETHTOOL_GWOL`` request."""
    return _WOL.pack(_Command.GWOL, 0, 0, bytes(6))


def decode_wake_on_lan(answer: bytes) -> JsonObject:
    """Return the wake-on-LAN modes the NIC supports and the ones enabled.

    The SecureOn password the structure also carries is a secret and is never read.

    Raises:
        ValueError: the answer is shorter than ``struct ethtool_wolinfo``.
    """
    _need(answer, _WOL.size, "ethtool wolinfo")
    _, supported, enabled, _ = _WOL.unpack_from(answer)
    return {"supported": _bits([supported], _WOL_MODES), "enabled": _bits([enabled], _WOL_MODES)}


def link_settings_request(words: int) -> bytes:
    """Return the ``ETHTOOL_GLINKSETTINGS`` request with room for three masks of ``words`` words.

    Ask with ``words=0`` first: the kernel answers with the size it needs
    (:func:`link_settings_words`), then ask again with that size.
    """
    head = bytearray(_LINK_SETTINGS.size)
    _U32.pack_into(head, 0, _Command.GLINKSETTINGS)
    struct.pack_into("<b", head, _NWORDS_OFFSET, words)
    return bytes(head) + bytes(3 * words * 4)


def link_settings_words(answer: bytes) -> int:
    """Return the mask size the kernel asks for, from the answer to the ``words=0`` request.

    Raises:
        ValueError: the answer is short, or the kernel did not state a size.
    """
    _need(answer, _LINK_SETTINGS.size, "ethtool link settings")
    words = struct.unpack_from("<b", answer, _NWORDS_OFFSET)[0]
    if words >= 0:
        raise ValueError("ethtool link settings: the kernel did not state its mask size")
    return -words


def decode_link_settings(answer: bytes, mode_names: Sequence[str]) -> JsonObject:
    """Return speed, duplex, connector, autonegotiation and the three link-mode masks by name.

    Raises:
        ValueError: the answer is shorter than its masks.
    """
    _need(answer, _LINK_SETTINGS.size, "ethtool link settings")
    _, speed, duplex, port, _, autoneg, _, _, _, words, *_ = _LINK_SETTINGS.unpack_from(answer)
    _need(answer, _LINK_SETTINGS.size + 3 * words * 4, "ethtool link settings")
    masks = struct.unpack_from(f"<{3 * words}I", answer, _LINK_SETTINGS.size)
    return {
        "speed_mbps": None if speed == _SPEED_UNKNOWN else speed,
        "duplex": _DUPLEXES.get(duplex, Duplex.UNKNOWN).value,
        "port": _PORTS.get(port, Port.OTHER).value,
        "autoneg": bool(autoneg),
        "supported": _bits(masks[:words], mode_names),
        "advertising": _bits(masks[words : 2 * words], mode_names),
        "link_partner_advertising": _bits(masks[2 * words :], mode_names),
    }


__all__ = [
    "CHANNELS",
    "COALESCE",
    "PAUSE",
    "RINGS",
    "Duplex",
    "FeatureState",
    "Port",
    "StringSet",
    "U32Fields",
    "decode_driver_info",
    "decode_features",
    "decode_link_settings",
    "decode_permanent_address",
    "decode_string_count",
    "decode_strings",
    "decode_wake_on_lan",
    "driver_info_request",
    "features_request",
    "link_settings_request",
    "link_settings_words",
    "permanent_address_request",
    "string_count_request",
    "strings_request",
    "wake_on_lan_request",
]
