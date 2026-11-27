"""The pure ``/proc/interrupts`` parser, fed tables written in the kernel's layout.

The layout is what ``show_interrupts()`` in ``kernel/irq/proc.c`` prints: a header of CPU names,
then one row per interrupt (``<irq>:``, one count per CPU, chip name, ``<hwirq>-<edge|level>``,
the actions) and the architecture's named counters (``NMI:``, ``LOC:``, ...).
"""

from __future__ import annotations

import pytest

from fingerprint_machine.domain.interrupts import parse_interrupts

_TABLE = (
    "           CPU0       CPU1\n"
    "  0:         21          0   IO-APIC   2-edge      timer\n"
    " 24:          5        700   PCI-MSIX-0000:03:00.0    0-edge      vmw_pvscsi\n"
    " 25:          0          0   PCI-MSI-0000:00:1c.0    0-edge      PCIe PME, pciehp\n"
    " 26:          0          0   PCI-MSI-0000:04:00.0  524288-edge\n"
    " 30:          1          2   XT-PIC      i8042\n"
    "NMI:          3          4   Non-maskable interrupts\n"
    "ERR:          0\n"
)


@pytest.mark.os_agnostic
def test_the_header_names_the_cpus() -> None:
    assert parse_interrupts(_TABLE).cpus == ("CPU0", "CPU1")


@pytest.mark.os_agnostic
def test_a_numbered_row_splits_into_counts_chip_hwirq_trigger_and_actions() -> None:
    row = parse_interrupts(_TABLE).by_irq()[24]
    assert row.as_json() == {
        "irq": 24,
        "name": "24",
        "per_cpu_counts": [5, 700],
        "chip": "PCI-MSIX-0000:03:00.0",
        "hwirq": "0",
        "trigger": "edge",
        "actions": ["vmw_pvscsi"],
        "description": None,
    }


@pytest.mark.os_agnostic
def test_several_actions_on_one_line_are_listed_each() -> None:
    assert parse_interrupts(_TABLE).by_irq()[25].actions == ("PCIe PME", "pciehp")


@pytest.mark.os_agnostic
def test_a_row_without_actions_has_none() -> None:
    row = parse_interrupts(_TABLE).by_irq()[26]
    assert (row.hwirq, row.trigger, row.actions) == ("524288", "edge", ())


@pytest.mark.os_agnostic
def test_a_row_in_the_older_layout_keeps_chip_and_actions() -> None:
    row = parse_interrupts(_TABLE).by_irq()[30]
    assert (row.chip, row.hwirq, row.trigger, row.actions) == ("XT-PIC", None, None, ("i8042",))


@pytest.mark.os_agnostic
def test_named_counters_keep_their_counts_and_description() -> None:
    named = parse_interrupts(_TABLE).named()
    assert [(r.name, r.per_cpu_counts, r.description) for r in named] == [
        ("NMI", (3, 4), "Non-maskable interrupts"),
        ("ERR", (0,), None),
    ]
    assert named[0].irq is None


@pytest.mark.os_agnostic
def test_every_numbered_row_is_found_by_its_irq() -> None:
    assert sorted(parse_interrupts(_TABLE).by_irq()) == [0, 24, 25, 26, 30]


@pytest.mark.os_agnostic
def test_a_table_without_a_cpu_header_is_refused() -> None:
    with pytest.raises(ValueError, match="CPU"):
        parse_interrupts("  0:  1  IO-APIC  2-edge  timer\n")
