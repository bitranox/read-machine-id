"""``/etc/resolv.conf`` parsed: resolver addresses, search domains, options (resolv.conf(5))."""

from __future__ import annotations

import pytest

from fingerprint_machine.domain.resolv import parse_resolv_conf


@pytest.mark.os_agnostic
def test_nameservers_search_domains_and_options_are_read_in_order() -> None:
    text = (
        "# generated\n"
        "nameserver 192.0.2.53\n"
        "nameserver 2001:db8::53 ; trailing comment\n"
        "domain example.test\n"
        "search old.example.test\n"
        "search example.test corp.example.test\n"
        "options edns0 ndots:2\n"
        "sortlist 192.0.2.0/255.255.255.0\n"
    )
    assert parse_resolv_conf(text).as_json() == {
        "nameservers": ["192.0.2.53", "2001:db8::53"],
        "domain": "example.test",
        "search": ["example.test", "corp.example.test"],
        "options": ["edns0", "ndots:2"],
        "sortlist": ["192.0.2.0/255.255.255.0"],
    }


@pytest.mark.os_agnostic
def test_an_empty_file_names_nothing() -> None:
    assert parse_resolv_conf("").as_json() == {
        "nameservers": [],
        "domain": None,
        "search": [],
        "options": [],
        "sortlist": [],
    }
