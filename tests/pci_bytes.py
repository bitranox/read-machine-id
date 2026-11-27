"""Build PCI configuration space images by hand, from the documented register layout.

Layouts follow the PCI Local Bus Specification 3.0 (chapter 6, configuration space) and the PCI
Express Base Specification (chapter 7, capability structures). Every identifier and serial number
here is invented.
"""

from __future__ import annotations

import struct

#: The capability IDs and extended capability IDs these images use.
CAP_PM = 0x01
CAP_MSI = 0x05
CAP_EXP = 0x10
CAP_MSIX = 0x11
EXT_AER = 0x01
EXT_DSN = 0x03
EXT_SRIOV = 0x10

#: The invented Device Serial Number planted in the endpoint image, and its printed form.
DSN_VALUE = 0x0050_56FF_FE12_3456
DSN_TEXT = "00-50-56-ff-fe-12-34-56"


class Config:
    """A configuration space image, written field by field."""

    def __init__(self, size: int) -> None:
        """Start an all-zero image of ``size`` bytes."""
        self.data = bytearray(size)

    def put(self, offset: int, fmt: str, *values: int) -> Config:
        """Write ``values`` little-endian at ``offset``."""
        struct.pack_into("<" + fmt, self.data, offset, *values)
        return self

    def cap(self, offset: int, cap_id: int, next_offset: int) -> Config:
        """Write a standard capability header."""
        return self.put(offset, "BB", cap_id, next_offset)

    def ext(self, offset: int, cap_id: int, next_offset: int, version: int = 1) -> Config:
        """Write an extended capability header."""
        return self.put(offset, "I", cap_id | (version << 16) | (next_offset << 20))

    def bytes(self, length: int | None = None) -> bytes:
        """The image, or its first ``length`` bytes (what an unprivileged read returns)."""
        return bytes(self.data if length is None else self.data[:length])


def endpoint_config() -> Config:
    """A PCIe endpoint with PM, MSI, PCIe and MSI-X capabilities, then AER, DSN and SR-IOV."""
    cfg = Config(4096)
    cfg.put(0x00, "HH", 0x15AD, 0x07C0)  # vendor, device
    cfg.put(0x04, "HH", 0x0407, 0x0010)  # command, status (capability list)
    cfg.put(0x08, "I", 0x01070002)  # revision 2, class 01 07 00 (SAS controller)
    cfg.put(0x0E, "B", 0x00)  # header type 0, single function
    cfg.put(0x2C, "HH", 0x15AD, 0x07C0)  # subsystem vendor, subsystem
    cfg.put(0x34, "B", 0x40)  # capabilities pointer
    cfg.put(0x3C, "BB", 11, 1)  # interrupt line 11, pin INTA
    cfg.cap(0x40, CAP_PM, 0x48)
    cfg.cap(0x48, CAP_MSI, 0x60).put(0x4A, "H", 0x0081 | (3 << 1) | (1 << 4))  # enabled, 8 capable, 2 on
    cfg.cap(0x60, CAP_EXP, 0x9C)
    cfg.put(0x62, "H", 0x0002 | (0x0 << 4))  # version 2, endpoint
    cfg.put(0x6C, "I", 0x3 | (8 << 4))  # link capabilities: 8.0 GT/s, x8
    cfg.cap(0x9C, CAP_MSIX, 0x00)
    cfg.put(0x9E, "H", 0x8000 | 31)  # enabled, 32 entries
    cfg.put(0xA0, "II", 0x2000 | 1, 0x3000 | 1)  # table BAR 1 at 0x2000, PBA BAR 1 at 0x3000
    cfg.ext(0x100, EXT_AER, 0x140, version=2)
    cfg.put(0x108, "II", 0x00400000, 0x00062030)  # uncorrectable mask, severity
    cfg.put(0x114, "I", 0x00002000)  # correctable mask
    cfg.ext(0x140, EXT_DSN, 0x150)
    cfg.put(0x144, "II", DSN_VALUE & 0xFFFFFFFF, DSN_VALUE >> 32)
    cfg.ext(0x150, EXT_SRIOV, 0x000)
    cfg.put(0x158, "H", 0x0001)  # VF enable
    cfg.put(0x15C, "HHH", 8, 16, 4)  # initial, total, num VFs
    cfg.put(0x164, "HH", 0x80, 0x2)  # first VF offset, stride
    cfg.put(0x16A, "H", 0x07C1)  # VF device id
    return cfg


def root_port_config() -> Config:
    """A PCIe root port (header type 1) with one PCIe capability that has a slot."""
    cfg = Config(4096)
    cfg.put(0x00, "HH", 0x8086, 0x1234)
    cfg.put(0x04, "HH", 0x0007, 0x0010)
    cfg.put(0x08, "I", 0x06040001)  # revision 1, class 06 04 00 (PCI bridge)
    cfg.put(0x0E, "B", 0x81)  # header type 1, multifunction
    cfg.put(0x18, "BBB", 0, 3, 5)  # primary, secondary, subordinate bus
    cfg.put(0x34, "B", 0x40)
    cfg.put(0x3C, "BB", 0xFF, 0)  # no legacy interrupt
    cfg.cap(0x40, CAP_EXP, 0x00)
    cfg.put(0x42, "H", 0x0002 | (0x4 << 4) | 0x100)  # root port, slot implemented
    cfg.put(0x54, "I", 7 << 19)  # slot capabilities: physical slot 7
    return cfg
