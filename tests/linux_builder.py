"""Build a synthetic Linux machine for the tests: a directory tree that mirrors ``/`` plus answers.

The tree holds the files a Linux reading asks for (``/sys``, ``/proc``, ``/etc``, ``/run``) and the
answers hold what is not a file (CPUID, ethtool, netlink, the TPM). Every value is invented.

Contents:
    * :func:`write_linux_tree` - write the files under a root directory.
    * :func:`linux_answers` - the non-file answers, as :class:`FixtureLinuxSource` takes them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from machine_builder import cpuid_document

if TYPE_CHECKING:
    from pathlib import Path

    from fingerprint_machine.domain.json_types import JsonObject

#: The files of a minimal KVM-like guest, relative to the tree root.
_FILES: dict[str, str] = {
    "etc/os-release": 'NAME="Example Linux"\nID=example\nVERSION_ID="1.0"\n',
    "etc/hostname": "test-guest\n",
    "proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Example CPU\n\n",
    "sys/class/dmi/id/sys_vendor": "Example Systems\n",
    "sys/class/dmi/id/product_name": "Model K\n",
}


def write_linux_tree(root: Path) -> Path:
    """Write the files of a minimal guest under ``root`` and return ``root``."""
    for relative, content in _FILES.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def linux_answers(*, hypervisor: bytes = b"KVMKVMKVM") -> JsonObject:
    """Return the non-file answers of the guest: CPUID only, so far."""
    return {"cpuid": cpuid_document(hypervisor=hypervisor)}


__all__ = ["linux_answers", "write_linux_tree"]
