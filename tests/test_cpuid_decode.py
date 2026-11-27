"""The pure CPUID decoder, fed hand-built register values.

Every register value here is built from the documented layout (Intel SDM vol. 2A "CPUID", AMD
APM vol. 3 "CPUID"), not captured from a machine.
"""

from __future__ import annotations

import pytest

from fingerprint_machine.domain.cpuid import (
    HYPERVISOR_BASES,
    CpuidQuery,
    CpuidRegs,
    basic_queries,
    decode_cpuid,
    extended_queries,
    hypervisor_answers,
    hypervisor_queries,
    leaf7_subqueries,
)


def _sig(text: bytes) -> tuple[int, int, int]:
    """Split a 12-byte signature into three little-endian registers, in the order given."""
    assert len(text) == 12
    return (
        int.from_bytes(text[0:4], "little"),
        int.from_bytes(text[4:8], "little"),
        int.from_bytes(text[8:12], "little"),
    )


def _vendor_leaf(max_leaf: int, vendor: bytes) -> CpuidRegs:
    # Leaf 0 spells the vendor in EBX, EDX, ECX.
    ebx, edx, ecx = _sig(vendor)
    return CpuidRegs(eax=max_leaf, ebx=ebx, ecx=ecx, edx=edx)


def _hypervisor_leaf(max_leaf: int, vendor: bytes) -> CpuidRegs:
    # A hypervisor base leaf spells its vendor in EBX, ECX, EDX.
    ebx, ecx, edx = _sig(vendor)
    return CpuidRegs(eax=max_leaf, ebx=ebx, ecx=ecx, edx=edx)


def _brand_leaves(brand: str) -> dict[CpuidQuery, CpuidRegs]:
    raw = brand.encode().ljust(48, b"\0")
    out: dict[CpuidQuery, CpuidRegs] = {}
    for i, leaf in enumerate((0x80000002, 0x80000003, 0x80000004)):
        chunk = raw[i * 16 : (i + 1) * 16]
        words = [int.from_bytes(chunk[j : j + 4], "little") for j in range(0, 16, 4)]
        out[CpuidQuery(leaf)] = CpuidRegs(eax=words[0], ebx=words[1], ecx=words[2], edx=words[3])
    return out


#: Family 6, model 0x3E, stepping 4: base model 0xE with extended model 3.
_SIGNATURE = 0x000306E4
_HYPERVISOR_BIT = 1 << 31


def _guest(hypervisor: dict[CpuidQuery, CpuidRegs]) -> dict[CpuidQuery, CpuidRegs]:
    answers = {
        CpuidQuery(0): _vendor_leaf(0x0D, b"GenuineIntel"),
        CpuidQuery(1): CpuidRegs(eax=_SIGNATURE, ebx=0x00020800, ecx=(1 << 0) | (1 << 5) | _HYPERVISOR_BIT, edx=1),
        CpuidQuery(7): CpuidRegs(eax=0, ebx=(1 << 5) | (1 << 9), ecx=0, edx=1 << 26),
        CpuidQuery(0x80000000): CpuidRegs(eax=0x80000008, ebx=0, ecx=0, edx=0),
        CpuidQuery(0x80000001): CpuidRegs(eax=0, ebx=0, ecx=1, edx=(1 << 20) | (1 << 29)),
        **_brand_leaves("  Example(R) CPU @ 2.70GHz"),
    }
    answers.update(hypervisor)
    return answers


@pytest.mark.os_agnostic
def test_vmware_signature_family_model_brand_and_flags() -> None:
    decoded = decode_cpuid(_guest({CpuidQuery(0x40000000): _hypervisor_leaf(0x40000010, b"VMwareVMware")}))
    assert decoded["vendor"] == "GenuineIntel"
    assert (decoded["family"], decoded["model"], decoded["stepping"]) == (6, 0x3E, 4)
    assert decoded["signature"] == "0x000306e4"
    assert decoded["brand"] == "Example(R) CPU @ 2.70GHz"
    assert decoded["max_basic_leaf"] == "0x0000000d"
    assert decoded["max_extended_leaf"] == "0x80000008"
    assert decoded["hypervisor_present_bit"] is True
    assert decoded["hypervisor_vendor"] == "VMwareVMware"
    assert decoded["hypervisors"] == [{"base": "0x40000000", "vendor": "VMwareVMware", "max_leaf": "0x40000010"}]
    features = decoded["features"]
    assert isinstance(features, dict)
    assert features["leaf_1_ecx"] == ["pni", "vmx", "hypervisor"]
    assert features["leaf_1_edx"] == ["fpu"]
    assert features["leaf_7_ebx"] == ["avx2", "erms"]
    assert features["leaf_7_edx"] == ["spec_ctrl"]
    assert features["leaf_80000001_ecx"] == ["lahf_lm"]
    assert features["leaf_80000001_edx"] == ["nx", "lm"]


@pytest.mark.os_agnostic
def test_kvm_signature_padded_with_nuls_reads_without_them() -> None:
    decoded = decode_cpuid(_guest({CpuidQuery(0x40000000): _hypervisor_leaf(0x40000001, b"KVMKVMKVM\0\0\0")}))
    assert decoded["hypervisor_vendor"] == "KVMKVMKVM"


@pytest.mark.os_agnostic
def test_hyperv_enlightenments_with_kvm_behind_them_list_both_bases() -> None:
    # A KVM guest with Hyper-V enlightenments answers "Microsoft Hv" at the first base and moves
    # its own signature to the next one: the second base is what tells it from real Hyper-V.
    decoded = decode_cpuid(
        _guest(
            {
                CpuidQuery(0x40000000): _hypervisor_leaf(0x4000000B, b"Microsoft Hv"),
                CpuidQuery(0x40000100): _hypervisor_leaf(0x40000101, b"KVMKVMKVM\0\0\0"),
            }
        )
    )
    assert decoded["hypervisor_vendor"] == "Microsoft Hv"
    assert decoded["hypervisors"] == [
        {"base": "0x40000000", "vendor": "Microsoft Hv", "max_leaf": "0x4000000b"},
        {"base": "0x40000100", "vendor": "KVMKVMKVM", "max_leaf": "0x40000101"},
    ]


@pytest.mark.os_agnostic
def test_bare_metal_has_no_hypervisor_even_though_the_range_returns_data() -> None:
    # Intel answers a leaf above its maximum with the highest basic leaf's data: not a signature.
    garbage = CpuidRegs(eax=0x00000A8C, ebx=0x00000E10, ecx=0x00000064, edx=0)
    answers = _guest({CpuidQuery(0x40000000): garbage})
    answers[CpuidQuery(1)] = CpuidRegs(eax=_SIGNATURE, ebx=0, ecx=0, edx=0)
    decoded = decode_cpuid(answers)
    assert decoded["hypervisor_present_bit"] is False
    assert decoded["hypervisors"] == []
    assert decoded["hypervisor_vendor"] is None
    assert not hypervisor_answers(0x40000000, garbage)


@pytest.mark.os_agnostic
def test_a_set_bit_without_a_documented_name_is_kept_by_number() -> None:
    answers = _guest({})
    answers[CpuidQuery(1)] = CpuidRegs(eax=_SIGNATURE, ebx=0, ecx=1 << 16, edx=1 << 10)
    features = decode_cpuid(answers)["features"]
    assert isinstance(features, dict)
    assert (features["leaf_1_ecx"], features["leaf_1_edx"]) == (["bit16"], ["bit10"])


@pytest.mark.os_agnostic
def test_extended_family_and_model_apply_to_family_15() -> None:
    # AMD Zen: base family 0xF, extended family 0x8 -> 0x17; extended model 3, base model 1 -> 0x31.
    answers = {CpuidQuery(0): _vendor_leaf(0x10, b"AuthenticAMD"), CpuidQuery(1): CpuidRegs(0x00830F10, 0, 0, 0)}
    decoded = decode_cpuid(answers)
    assert (decoded["vendor"], decoded["family"], decoded["model"], decoded["stepping"]) == (
        "AuthenticAMD",
        0x17,
        0x31,
        0,
    )


@pytest.mark.os_agnostic
def test_only_leaf_0_decodes_what_it_can_and_leaves_the_rest_none() -> None:
    decoded = decode_cpuid({CpuidQuery(0): _vendor_leaf(1, b"GenuineIntel")})
    assert decoded["vendor"] == "GenuineIntel"
    assert decoded["family"] is None
    assert decoded["brand"] is None
    assert decoded["max_extended_leaf"] is None
    assert decoded["hypervisor_present_bit"] is None


@pytest.mark.os_agnostic
def test_queries_follow_the_maximum_leaves() -> None:
    assert basic_queries(_vendor_leaf(0x0D, b"GenuineIntel")) == [
        CpuidQuery(1),
        CpuidQuery(7),
        CpuidQuery(0x0D),
        CpuidQuery(0x0D, 1),
    ]
    assert basic_queries(_vendor_leaf(5, b"GenuineIntel")) == [CpuidQuery(1)]
    assert leaf7_subqueries(CpuidRegs(eax=2, ebx=0, ecx=0, edx=0)) == [CpuidQuery(7, 1), CpuidQuery(7, 2)]
    assert leaf7_subqueries(CpuidRegs(eax=99, ebx=0, ecx=0, edx=0))[-1] == CpuidQuery(7, 3)
    assert extended_queries(CpuidRegs(eax=0x80000004, ebx=0, ecx=0, edx=0)) == [
        CpuidQuery(0x80000001),
        CpuidQuery(0x80000002),
        CpuidQuery(0x80000003),
        CpuidQuery(0x80000004),
    ]
    # A CPU without extended leaves answers 0x80000000 with something below it.
    assert extended_queries(CpuidRegs(eax=0x0D, ebx=0, ecx=0, edx=0)) == []


@pytest.mark.os_agnostic
def test_hypervisor_queries_stay_inside_their_base_range() -> None:
    vmware = _hypervisor_leaf(0x40000003, b"VMwareVMware")
    assert hypervisor_queries(0x40000000, vmware) == [
        CpuidQuery(0x40000001),
        CpuidQuery(0x40000002),
        CpuidQuery(0x40000003),
    ]
    # A maximum of 0 means "only the next leaf" (older KVM); a maximum past the range is capped.
    assert hypervisor_queries(0x40000000, _hypervisor_leaf(0, b"KVMKVMKVM\0\0\0")) == [CpuidQuery(0x40000001)]
    capped = hypervisor_queries(0x40000100, _hypervisor_leaf(0x4000FFFF, b"XenVMMXenVMM"))
    assert (len(capped), capped[0], capped[-1]) == (255, CpuidQuery(0x40000101), CpuidQuery(0x400001FF))
    assert hypervisor_queries(0x40000000, _hypervisor_leaf(0x40000000, b"VMwareVMware")) == []
    assert HYPERVISOR_BASES[0] == 0x40000000
    assert HYPERVISOR_BASES[-1] == 0x4000FF00


@pytest.mark.os_agnostic
def test_registers_and_queries_render_as_fixed_width_hex() -> None:
    assert CpuidRegs(eax=1, ebx=0xFFFFFFFF, ecx=0, edx=0x10).as_json() == {
        "eax": "0x00000001",
        "ebx": "0xffffffff",
        "ecx": "0x00000000",
        "edx": "0x00000010",
    }
    assert CpuidQuery(0x40000100).key == "0x40000100:0"
    assert CpuidQuery(7, 1).key == "0x00000007:1"


@pytest.mark.os_agnostic
def test_every_bit_of_every_feature_word_has_a_name_or_a_number() -> None:
    every = CpuidRegs(eax=0, ebx=0xFFFFFFFF, ecx=0xFFFFFFFF, edx=0xFFFFFFFF)
    answers = {CpuidQuery(1): every, CpuidQuery(7): every, CpuidQuery(0x80000001): every}
    features = decode_cpuid(answers)["features"]
    assert isinstance(features, dict)
    for word, names in features.items():
        assert isinstance(names, list), word
        assert len(names) == 32, word
        assert len(set(names)) == 32, word
