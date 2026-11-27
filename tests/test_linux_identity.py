"""Identity values derived from Linux-shaped inputs: the PVSCSI sasWWID from PCI ids and a DSN."""

from __future__ import annotations

import pytest

from fingerprint_machine.domain.identity import vmware_pvscsi_sas_wwid, vmware_pvscsi_sas_wwid_from_dsn


@pytest.mark.os_agnostic
def test_the_dsn_of_a_pvscsi_controller_gives_the_same_wwid_windows_derives() -> None:
    windows = vmware_pvscsi_sas_wwid("PCI\\VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02\\0123ABCD5005056000")
    linux = vmware_pvscsi_sas_wwid_from_dsn(vendor=0x15AD, device=0x07C0, dsn=0x0123ABCD50050560)
    assert linux == windows == "500505600123abcd"


@pytest.mark.os_agnostic
def test_another_device_has_no_pvscsi_wwid() -> None:
    assert vmware_pvscsi_sas_wwid_from_dsn(vendor=0x1AF4, device=0x1004, dsn=0x0123ABCD50050560) is None
