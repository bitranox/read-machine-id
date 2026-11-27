"""The pure decoders behind the Linux system sections, fed hand-built bytes and text."""

from __future__ import annotations

import json
import struct

import pytest

from fingerprint_machine.domain.efivars import decode_efivar_flag
from fingerprint_machine.domain.luks import decode_luks_header, luks_header_size
from fingerprint_machine.domain.procfs import (
    parse_cpuinfo,
    parse_meminfo,
    parse_module_names,
    parse_os_release,
)
from fingerprint_machine.domain.smbios_entry import decode_smbios_entry_point
from fingerprint_machine.domain.virt import VirtKind, detect_virt

# --------------------------------------------------------------------------------------------
# SMBIOS entry point
# --------------------------------------------------------------------------------------------


def _sm3(major: int, minor: int) -> bytes:
    return b"_SM3_" + bytes([0, 0x18, major, minor, 4, 1, 0]) + struct.pack("<IQ", 0x14EF, 0x725D3000)


def _sm2(major: int, minor: int) -> bytes:
    head = b"_SM_" + bytes([0, 0x1F, major, minor]) + struct.pack("<H", 0x100) + bytes(6)
    return head + b"_DMI_" + bytes([0]) + struct.pack("<HIH", 0x0ABC, 0x000F0000, 42) + bytes([0x27])


@pytest.mark.os_agnostic
def test_an_smbios3_entry_point_gives_the_version_and_table_bounds() -> None:
    entry = decode_smbios_entry_point(_sm3(3, 6))
    assert entry.version == "3.6"
    assert entry.as_json() == {
        "anchor": "_SM3_",
        "version": "3.6",
        "docrev": 4,
        "table_length": 0x14EF,
        "table_address": "0x725d3000",
        "structure_count": None,
    }


@pytest.mark.os_agnostic
def test_an_smbios2_entry_point_gives_the_version_and_structure_count() -> None:
    entry = decode_smbios_entry_point(_sm2(2, 8))
    assert (entry.version, entry.table_length, entry.structure_count) == ("2.8", 0x0ABC, 42)
    assert entry.as_json()["table_address"] == "0x000f0000"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("raw", [b"", b"_SM3_\0", b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"])
def test_an_entry_point_that_is_short_or_unknown_is_refused(raw: bytes) -> None:
    with pytest.raises(ValueError, match="entry point"):
        decode_smbios_entry_point(raw)


# --------------------------------------------------------------------------------------------
# procfs and /etc text
# --------------------------------------------------------------------------------------------

_CPUINFO = (
    "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Example CPU @ 2.70GHz\n"
    "flags\t\t: fpu vme hypervisor\nbugs\t\t: spectre_v1 mds\npower management:\n\n"
    "processor\t: 1\nvendor_id\t: GenuineIntel\nflags\t\t: fpu\n\n"
)


@pytest.mark.os_agnostic
def test_cpuinfo_is_one_object_per_logical_cpu_with_flags_as_lists() -> None:
    cpus = parse_cpuinfo(_CPUINFO)
    assert cpus == [
        {
            "processor": "0",
            "vendor_id": "GenuineIntel",
            "model_name": "Example CPU @ 2.70GHz",
            "flags": ["fpu", "vme", "hypervisor"],
            "bugs": ["spectre_v1", "mds"],
            "power_management": [],
        },
        {"processor": "1", "vendor_id": "GenuineIntel", "flags": ["fpu"]},
    ]


@pytest.mark.os_agnostic
def test_meminfo_turns_kilobytes_into_bytes_and_keeps_counts() -> None:
    text = "MemTotal:       16318636 kB\nHugePages_Total:       4\nHugepagesize:       2048 kB\nbogus line\n"
    assert parse_meminfo(text) == {"MemTotal": 16318636 * 1024, "HugePages_Total": 4, "Hugepagesize": 2097152}


@pytest.mark.os_agnostic
def test_os_release_unquotes_values_and_skips_comments() -> None:
    text = '# comment\nNAME="Example Linux"\nID=example\nPRETTY_NAME=\'Example 1.0 "LTS"\'\nBAD LINE\n\nX="a\\"b"\n'
    assert parse_os_release(text) == {
        "NAME": "Example Linux",
        "ID": "example",
        "PRETTY_NAME": 'Example 1.0 "LTS"',
        "X": 'a"b',
    }


@pytest.mark.os_agnostic
def test_module_names_are_the_first_column_of_proc_modules() -> None:
    text = "nf_tables 372736 1 nft_ct, Live 0x0\nvmw_pvscsi 28672 2 - Live 0x0\n\n"
    assert parse_module_names(text) == ["nf_tables", "vmw_pvscsi"]


# --------------------------------------------------------------------------------------------
# efivars
# --------------------------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_an_efivar_flag_is_the_byte_after_the_attributes() -> None:
    attributes = struct.pack("<I", 0x06)
    assert decode_efivar_flag(attributes + b"\x01") is True
    assert decode_efivar_flag(attributes + b"\x00") is False
    with pytest.raises(ValueError, match="efivar"):
        decode_efivar_flag(attributes)


# --------------------------------------------------------------------------------------------
# detect-virt
# --------------------------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_dmi_vendor_names_the_hypervisor_before_cpuid_does() -> None:
    verdict = detect_virt(cpuid_vendor="KVMKVMKVM", hypervisor_bit=True, dmi={"sys_vendor": "Amazon EC2"})
    assert (verdict.kind, verdict.source) == (VirtKind.AMAZON, "dmi sys_vendor")


@pytest.mark.os_agnostic
def test_a_kvm_guest_whose_dmi_says_qemu_is_kvm_as_cpuid_says() -> None:
    verdict = detect_virt(cpuid_vendor="KVMKVMKVM", hypervisor_bit=True, dmi={"sys_vendor": "QEMU"})
    assert (verdict.kind, verdict.source) == (VirtKind.KVM, "cpuid 0x40000000")


@pytest.mark.os_agnostic
def test_cpuid_names_the_hypervisor_when_dmi_is_silent() -> None:
    verdict = detect_virt(cpuid_vendor="VMwareVMware", hypervisor_bit=True, dmi={"sys_vendor": "Example"})
    assert (verdict.kind, verdict.source) == (VirtKind.VMWARE, "cpuid 0x40000000")
    assert verdict.as_json() == {"kind": "vmware", "source": "cpuid 0x40000000", "matched": "VMwareVMware"}


@pytest.mark.os_agnostic
def test_an_unknown_hypervisor_with_the_bit_set_is_some_vm() -> None:
    verdict = detect_virt(cpuid_vendor="NoSuchHvVend", hypervisor_bit=True, dmi={})
    assert (verdict.kind, verdict.source) == (VirtKind.OTHER, "cpuid hypervisor bit")


@pytest.mark.os_agnostic
def test_no_hypervisor_signal_is_bare_metal_and_nothing_asked_is_unknown() -> None:
    assert detect_virt(cpuid_vendor=None, hypervisor_bit=False, dmi={"sys_vendor": "Dell Inc."}).kind is VirtKind.NONE
    assert detect_virt(cpuid_vendor=None, hypervisor_bit=None, dmi={}).kind is VirtKind.UNKNOWN


@pytest.mark.os_agnostic
def test_qemu_dmi_and_hyper_v_dmi_are_recognised() -> None:
    assert detect_virt(cpuid_vendor=None, hypervisor_bit=None, dmi={"sys_vendor": "QEMU"}).kind is VirtKind.QEMU
    hyperv = {"sys_vendor": "Microsoft Corporation", "product_name": "Virtual Machine"}
    assert detect_virt(cpuid_vendor=None, hypervisor_bit=None, dmi=hyperv).kind is VirtKind.MICROSOFT


# --------------------------------------------------------------------------------------------
# LUKS
# --------------------------------------------------------------------------------------------

_LUKS1_UUID = b"11111111-2222-3333-4444-555555555555"


def _luks1() -> bytes:
    header = bytearray(592)
    header[0:6] = b"LUKS\xba\xbe"
    header[6:8] = struct.pack(">H", 1)
    header[8:13] = b"aes\0\0"
    header[40:52] = b"xts-plain64\0"
    header[72:78] = b"sha256"
    header[104:112] = struct.pack(">II", 4096, 64)
    header[112:132] = b"D" * 20  # the master key digest: never returned
    header[168 : 168 + len(_LUKS1_UUID)] = _LUKS1_UUID
    header[208:216] = b"KEYSLOT!"  # a key slot: never returned
    return bytes(header)


def _luks2() -> bytes:
    area = {
        "keyslots": {"0": {"type": "luks2", "area": {"key_size": 64}}},
        "tokens": {},
        "segments": {
            "0": {
                "type": "crypt",
                "offset": "16777216",
                "size": "dynamic",
                "iv_tweak": "0",
                "encryption": "aes-xts-plain64",
                "sector_size": 512,
            }
        },
        "digests": {"0": {"type": "pbkdf2", "digest": "SECRETDIGEST"}},
        "config": {"json_size": "12288", "keyslots_size": "16744448"},
    }
    header = bytearray(4096)
    header[0:6] = b"LUKS\xba\xbe"
    header[6:8] = struct.pack(">H", 2)
    header[8:16] = struct.pack(">Q", 16384)
    header[24:29] = b"vault"
    header[72:78] = b"sha256"
    header[104:110] = b"SALTSA"  # the salt: never returned
    header[168 : 168 + len(_LUKS1_UUID)] = _LUKS1_UUID
    body = json.dumps(area).encode().ljust(16384 - 4096, b"\0")
    return bytes(header) + body


@pytest.mark.os_agnostic
def test_a_luks1_header_gives_cipher_and_uuid_and_never_the_key_material() -> None:
    raw = _luks1()
    assert luks_header_size(raw[:4096]) == 592
    decoded = decode_luks_header(raw)
    assert decoded == {
        "version": 1,
        "uuid": _LUKS1_UUID.decode(),
        "cipher_name": "aes",
        "cipher_mode": "xts-plain64",
        "hash_spec": "sha256",
        "payload_offset": 4096,
        "key_bytes": 64,
    }
    assert "KEYSLOT" not in json.dumps(decoded) and "DDDD" not in json.dumps(decoded)


@pytest.mark.os_agnostic
def test_a_luks2_header_gives_the_segments_and_never_keyslots_or_digests() -> None:
    raw = _luks2()
    assert luks_header_size(raw[:4096]) == 16384
    decoded = decode_luks_header(raw)
    assert (decoded["version"], decoded["uuid"], decoded["label"], decoded["checksum_alg"]) == (
        2,
        _LUKS1_UUID.decode(),
        "vault",
        "sha256",
    )
    assert decoded["segments"] == [
        {"type": "crypt", "offset": "16777216", "size": "dynamic", "encryption": "aes-xts-plain64", "sector_size": 512}
    ]
    text = json.dumps(decoded)
    assert all(secret not in text for secret in ("SECRETDIGEST", "keyslots", "key_size", "SALTSA", "digests"))


@pytest.mark.os_agnostic
def test_a_device_without_the_luks_magic_is_refused() -> None:
    with pytest.raises(ValueError, match="LUKS"):
        luks_header_size(bytes(4096))
    with pytest.raises(ValueError, match="LUKS"):
        decode_luks_header(b"LUKS\xba\xbe" + struct.pack(">H", 9) + bytes(600))
