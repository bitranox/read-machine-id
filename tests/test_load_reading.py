"""Loading a saved reading: what is accepted, and what is refused before memory runs out."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fingerprint_machine.application.readings import MAX_READING_BYTES, load_reading
from fingerprint_machine.domain.machine_errors import NotAReadingError


def _write(path: Path, document: object) -> int:
    raw = json.dumps(document).encode("utf-8")
    path.write_bytes(raw)
    return len(raw)


@pytest.mark.os_agnostic
def test_a_reading_at_the_cap_loads_and_one_byte_over_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "reading.json"
    size = _write(path, {"meta": {"label": "vm"}, "pad": "x" * 3000})
    assert load_reading(path, max_bytes=size)["meta"] == {"label": "vm"}
    with pytest.raises(NotAReadingError, match=rf"reading\.json: more than {size - 1} bytes"):
        load_reading(path, max_bytes=size - 1)


@pytest.mark.os_agnostic
def test_the_default_cap_leaves_room_for_a_large_real_reading() -> None:
    # Real readings measured 1-5 MB, a two-reading comparison 11 MB.
    assert MAX_READING_BYTES >= 64 * 1024 * 1024


@pytest.mark.os_posix
@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="needs /dev/zero")
def test_an_endless_device_is_refused_not_read_forever() -> None:
    with pytest.raises(NotAReadingError, match="more than 1000 bytes"):
        load_reading(Path("/dev/zero"), max_bytes=1000)


@pytest.mark.os_agnostic
def test_a_file_that_is_not_utf8_is_not_a_reading(tmp_path: Path) -> None:
    path = tmp_path / "latin1.json"
    path.write_bytes(b'{"meta": {"label": "\xe9"}}')
    with pytest.raises(NotAReadingError, match=r"latin1\.json"):
        load_reading(path)
