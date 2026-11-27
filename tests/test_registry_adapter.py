"""The real lib_registry adapter, over fake_winreg.

lib_registry picks fake_winreg off Windows at import time, so these tests drive the production
adapter for real on Linux and macOS. On Windows the same code would write the live registry,
so they are kept off it.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest
from lib_registry import Registry

from read_machine_id.adapters.fixture import FixtureSources
from read_machine_id.adapters.windows.registry import LibRegistrySource
from read_machine_id.application.collect import Section, read_section
from read_machine_id.application.machine_ports import Sources
from read_machine_id.domain.machine_errors import MissingKeyError

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def scratch_key() -> Iterator[str]:
    """A key of its own under HKCU, deleted afterwards (the fake registry is process-wide)."""
    key = rf"HKCU\Software\read-machine-id-test-{uuid.uuid4().hex}"
    registry = Registry()
    registry.create_key(key, parents=True)
    registry.create_key(key + r"\Child B")
    registry.create_key(key + r"\child a")
    registry.set_value(key, "Text", "hello")
    registry.set_value(key, "Blob", b"\x01\x02")
    registry.set_value(key, "Number", 7)
    yield key
    registry.delete_key(key, missing_ok=True, delete_subkeys=True)


@pytest.mark.os_posix
def test_values_and_subkeys_come_back_typed_and_sorted(scratch_key: str) -> None:
    source = LibRegistrySource()
    assert source.values(scratch_key) == {"Text": "hello", "Blob": b"\x01\x02", "Number": 7}
    assert source.subkeys(scratch_key) == ["child a", "Child B"]


@pytest.mark.os_posix
@pytest.mark.parametrize("method", ["values", "subkeys"])
def test_a_missing_key_is_reported_as_missing(method: str) -> None:
    with pytest.raises(MissingKeyError, match="read-machine-id-missing"):
        getattr(LibRegistrySource(), method)(r"HKCU\Software\read-machine-id-missing")


@pytest.mark.os_posix
def test_the_windows_section_reads_through_lib_registry() -> None:
    # fake_winreg's default registry carries a CurrentVersion key, as a real Windows does.
    nothing = FixtureSources({})
    section = read_section(Sources(platform=nothing, registry=LibRegistrySource()), Section.WINDOWS)
    assert isinstance(section, dict)
    current = section["current_version"]
    assert isinstance(current, dict)
    assert list(current) == ["CurrentBuild"]
