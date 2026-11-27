"""The filesystem side of a Linux source: what each failure is reported as.

The real source and the fixture read files the same way (the fixture under a directory that
mirrors ``/``), so these run against a temporary tree on any POSIX machine.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

import pytest

from fingerprint_machine.adapters.fixture import FixtureLinuxSource
from fingerprint_machine.adapters.linux.sysfs import FilesystemReader, SysfsLinuxSource
from fingerprint_machine.application.machine_ports import NetlinkDump
from fingerprint_machine.domain.ethtool import driver_info_request
from fingerprint_machine.domain.machine_errors import MissingPathError, NeedsRootError, SourceError
from fingerprint_machine.domain.netlink import decode_link

if TYPE_CHECKING:
    from pathlib import Path

    from fingerprint_machine.domain.json_types import JsonObject


def _tree(root: Path) -> FilesystemReader:
    (root / "sys/class/net/eth0").mkdir(parents=True)
    # Bytes, not write_text: Windows would write the newline as CRLF and no sysfs file holds one.
    (root / "sys/class/net/eth0/address").write_bytes(b"02:00:00:00:00:01\n")
    (root / "sys/class/net/lo").mkdir()
    (root / "proc").mkdir()
    (root / "proc/big").write_bytes(b"x" * 100)
    return FilesystemReader(root)


@pytest.mark.os_agnostic
def test_files_and_directories_read_under_the_root(tmp_path: Path) -> None:
    reader = _tree(tmp_path)
    assert reader.read_text("/sys/class/net/eth0/address") == "02:00:00:00:00:01\n"
    assert reader.read_bytes("/sys/class/net/eth0/address") == b"02:00:00:00:00:01\n"
    assert reader.list_dir("/sys/class/net") == ["eth0", "lo"]


@pytest.mark.os_agnostic
def test_a_missing_path_is_reported_as_missing(tmp_path: Path) -> None:
    reader = _tree(tmp_path)
    with pytest.raises(MissingPathError, match="/sys/class/tpm"):
        reader.list_dir("/sys/class/tpm")
    with pytest.raises(MissingPathError):
        reader.read_bytes("/sys/class/net/eth0/address/inside-a-file")


@pytest.mark.os_agnostic
def test_a_file_over_the_cap_is_refused_not_read_whole(tmp_path: Path) -> None:
    reader = _tree(tmp_path)
    assert reader.read_bytes("/proc/big", max_bytes=100) == b"x" * 100
    with pytest.raises(SourceError, match="more than 99 bytes"):
        reader.read_bytes("/proc/big", max_bytes=99)


@pytest.mark.os_agnostic
def test_a_file_longer_than_one_read_comes_back_whole_and_in_order(tmp_path: Path) -> None:
    content = bytes(range(256)) * 1000  # 256,000 bytes: several reads of any sane chunk size
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/long").write_bytes(content)
    reader = FilesystemReader(tmp_path)
    assert reader.read_bytes("/proc/long") == content
    assert reader.read_bytes("/proc/long", max_bytes=len(content)) == content
    with pytest.raises(SourceError, match=f"more than {len(content) - 1} bytes"):
        reader.read_bytes("/proc/long", max_bytes=len(content) - 1)
    assert reader.read_prefix("/proc/long", size=200_000) == content[:200_000]


@pytest.mark.os_agnostic
def test_a_relative_path_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="absolute"):
        _tree(tmp_path).read_text("sys/class/net/eth0/address")


@pytest.mark.os_posix
def test_a_link_reads_as_its_target_and_a_file_is_not_a_link(tmp_path: Path) -> None:
    reader = _tree(tmp_path)
    (tmp_path / "sys/class/net/eth0/device").symlink_to("../../../devices/pci0000:00/0000:00:03.0")
    assert reader.readlink("/sys/class/net/eth0/device") == "../../../devices/pci0000:00/0000:00:03.0"
    with pytest.raises(SourceError, match="not a link"):
        reader.readlink("/sys/class/net/eth0/address")


@pytest.mark.os_posix
def test_a_file_only_root_may_read_needs_root(tmp_path: Path) -> None:
    if sys.platform != "win32" and os.geteuid() == 0:
        pytest.skip("root reads a mode-000 file")
    reader = _tree(tmp_path)
    secret = tmp_path / "sys/class/net/eth0/address"
    secret.chmod(0)
    try:
        with pytest.raises(NeedsRootError, match="needs root"):
            reader.read_text("/sys/class/net/eth0/address")
    finally:
        secret.chmod(0o644)


@pytest.mark.os_agnostic
def test_the_real_source_refuses_an_overlong_interface_name() -> None:
    with pytest.raises(SourceError, match="longer than 15 bytes"):
        SysfsLinuxSource().ethtool("x" * 16, request=bytes(8))


@pytest.mark.os_linux
def test_the_real_source_dumps_the_links_and_asks_the_loopback_driver() -> None:
    source = SysfsLinuxSource()
    names = [str(decode_link(message).get("name")) for message in source.netlink_dump(NetlinkDump.LINKS)]
    assert "lo" in names
    # The loopback has no driver to describe itself: the kernel answers EOPNOTSUPP.
    with pytest.raises(SourceError, match=r"ENOTSUP|EOPNOTSUPP"):
        source.ethtool("lo", request=driver_info_request())


@pytest.mark.os_agnostic
def test_the_fixture_answers_kernel_interfaces_from_its_document(tmp_path: Path) -> None:
    answers: JsonObject = {
        "ethtool": {"eth0": {"0b000000": "0b000000ffff"}},
        "netlink": {"links": ["0102", "0304"]},
        "tpm_nv": {"0x01c00002": "3082"},
    }
    source = FixtureLinuxSource(tmp_path, answers)
    assert source.ethtool("eth0", request=bytes.fromhex("0b000000")) == bytes.fromhex("0b000000ffff")
    assert list(source.netlink_dump(NetlinkDump.LINKS)) == [b"\x01\x02", b"\x03\x04"]
    assert source.tpm_nv_read(0x01C00002) == b"\x30\x82"
    with pytest.raises(SourceError, match="not recorded"):
        source.netlink_dump(NetlinkDump.ROUTES)
    with pytest.raises(SourceError, match="not recorded"):
        source.ethtool("eth1", request=bytes(4))


@pytest.mark.os_agnostic
def test_the_fixture_answers_a_recorded_link_without_a_real_one(tmp_path: Path) -> None:
    _tree(tmp_path)
    target = "../../devices/pci0000:00/0000:00:03.0/net/eth0"
    source = FixtureLinuxSource(tmp_path, {"links": {"/sys/class/net/eth0": target}})
    assert source.readlink("/sys/class/net/eth0") == target
    with pytest.raises(SourceError, match="not a link"):
        source.readlink("/sys/class/net/eth0/address")
