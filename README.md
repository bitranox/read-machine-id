# fingerprint-machine

<!-- Badges -->
[![CI](https://github.com/bitranox/fingerprint-machine/actions/workflows/default_cicd_public.yml/badge.svg)](https://github.com/bitranox/fingerprint-machine/actions/workflows/default_cicd_public.yml)
[![CodeQL](https://github.com/bitranox/fingerprint-machine/actions/workflows/codeql.yml/badge.svg)](https://github.com/bitranox/fingerprint-machine/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/fingerprint-machine.svg)](https://pypi.org/project/fingerprint-machine/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/fingerprint-machine.svg)](https://pypi.org/project/fingerprint-machine/)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-46A3FF?logo=ruff&labelColor=000)](https://docs.astral.sh/ruff/)
[![codecov](https://codecov.io/gh/bitranox/fingerprint-machine/graph/badge.svg)](https://codecov.io/gh/bitranox/fingerprint-machine)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

`fingerprint-machine` reads what a Windows machine reports about itself and writes it out as one JSON
document: the SMBIOS table, every network adapter with its PCI location and driver settings, disk
and controller serials, every device Windows has seen, the Windows ids and licensing state, and the
TPM and Secure Boot state. It can also compare two such readings field by field.

What it is for:

- You move a machine to other hardware or another hypervisor and want to know which identity
  values changed: system UUID, serials, MAC addresses, NIC slot numbers, disk ids, the Windows
  device id. Any of them can break licensing, activation or a driver binding.
- You keep a baseline of a machine and check later that nothing drifted.
- You want a hardware and identity inventory from a script, as JSON rather than screen text.

It works on any Windows machine, physical or virtual. Reading needs Windows; comparing two saved
readings also works on Linux and macOS.

---

## Quick start

On the Windows machine, with [uv](https://docs.astral.sh/uv/) installed:

```powershell
# Read this machine, show a summary, and save the whole reading
uvx fingerprint-machine collect --out before.json

# Later, or after the move: read again and compare with the saved one
uvx fingerprint-machine check before.json --save after.json --diff-only

# Compare two saved readings anywhere, Linux and macOS included
uvx fingerprint-machine compare before.json after.json --diff-only
```

Run it from an elevated prompt if you can. Some sources, BitLocker among them, answer only to an
administrator. Without elevation those questions are skipped and listed, and the rest of the
reading is not affected.

---

## Commands

### `collect`

```text
fingerprint-machine collect [--section NAME ...] [--label TEXT] [--out FILE] [--json | --json-bare]
```

Reads the machine. Without options it prints a summary table. `--json` prints the whole reading
inside an envelope, `--json-bare` prints only the reading. `--out` also saves the reading to a
file, `--label` names it (default: the computer name), and `--section` reads only the sections you
name, e.g. `--section network --section smbios`.

### `compare`

```text
fingerprint-machine compare ORIGINAL ACTUAL [--diff-only] [--out FILE] [--json | --json-bare]
```

Compares two saved readings and marks every field as same, different, or present on one side only.
Exits 1 when anything differs. `--out` saves the comparison.

### `check`

```text
fingerprint-machine check BASELINE [--diff-only] [--save FILE] [--out FILE] [--json | --json-bare]
```

Reads this machine and compares it with a saved baseline in one step. `--save` keeps the fresh
reading and `--out` keeps the comparison. Exits 1 when anything differs.

### Exit codes and JSON

| Exit code | Meaning                                                                    |
|-----------|----------------------------------------------------------------------------|
| 0         | done; for `compare` and `check`, no differences                            |
| 1         | `compare` or `check` found differences                                     |
| 2         | refused: not Windows (`collect`, `check`), or a file that is not a reading |

`--json` wraps the result as `{"ok": true, "command": ..., "data": ..., "skipped": [...]}`.
`skipped` lists each question a source could not answer, with the reason, for example a WMI class
the machine does not provide. A failure prints `{"ok": false, "command": ..., "error": {"type":
..., "message": ...}}`. `--json-bare` prints only the data, and still prints JSON when it fails.
Warnings go to standard error, so standard output can go straight into `jq` or a file.

---

## What a reading holds

A reading starts with `meta` (tool version, schema version, time, label) and a `summary` of the
values people look for most:

```json
{
  "system": {
    "manufacturer": "Example Systems",
    "product": "Model X",
    "serial": "SER-0001",
    "uuid": "04030201-0605-0807-090A-0B0C0D0E0F10",
    "sku": "SKU-9",
    "family": "Family Y",
    "bios_version": "V1.2"
  },
  "nics": [
    {
      "name": "Ethernet0",
      "description": "vmxnet3 Ethernet Adapter",
      "mac": "005056000001",
      "interface_index": 6,
      "pci_serial": "000C29FFFF000001",
      "bus": 11, "device": 0, "function": 0, "slot": 160,
      "class_key": "0007"
    }
  ],
  "windows": {
    "edition": "Professional",
    "build": "26100.1000",
    "product_id": "00330-80000-00000-AA111",
    "device_id": "{DDDDDDDD-0000-0000-0000-000000000001}",
    "machine_guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "machine_sid": "S-1-5-21-1000-2000-3000",
    "license_status": 1,
    "partial_product_key": "JK7LZ"
  },
  "security": { "firmware_type": "UEFI", "secure_boot": 1, "tpm_version": "2.0", "vbs_status": 0 }
}
```

The values above are made up. The summary also has `cpu`, `memory`, `disks` and
`scsi_controllers`; for a VMware PVSCSI controller the summary works out its SAS WWID from the
controller's PCI serial.

The full sections follow the summary. `--section` reads any of them alone:

| Section    | What it holds                                                                                                                                       |
|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `smbios`   | The raw SMBIOS table with every structure; BIOS, system, board, chassis, CPU, slots, memory, OEM strings and onboard devices decoded field by field |
| `acpi`     | ACPI table headers (OEM ids), and whether an MSDM table holds a product key                                                                         |
| `platform` | BIOS, computer system (domain or workgroup included), product, baseboard and enclosure from WMI, and the BIOS and system values in the registry     |
| `cpu`      | Processors and caches                                                                                                                               |
| `memory`   | Memory modules and arrays                                                                                                                           |
| `disks`    | Disks, physical disks, partitions and volumes with their serials and GUIDs, and SAS or Fibre Channel initiator ports                                |
| `network`  | Per adapter: PCI location, every advanced driver setting, offloads, RSS, power management, bindings, the network class key, addresses, routes, DNS  |
| `hardware` | SCSI, IDE and USB controllers, CD drives, keyboards, mice, sound, monitors, serial ports, video                                                     |
| `devices`  | Every device instance under the registry's `Enum` key, present or not, with hardware ids, location and driver                                       |
| `windows`  | Operating system, the `CurrentVersion` key, device id, MachineGuid, machine SID, TCP/IP names, time zone, licensing, hotfixes, cloud join           |
| `security` | TPM (WMI and TBS), cached EK certificates (public fields only), Secure Boot, Device Guard and VBS, BitLocker status                                 |
| `services` | Every service with its state and start mode                                                                                                         |

A question that cannot be answered (a missing WMI class, access denied) is recorded as
`{"error": "..."}` in its place and listed under `skipped`, and the reading goes on.

### What it never writes

- Product keys are cut to their last five characters wherever they turn up: the
  `OA3xOriginalProductKey` value, the ACPI MSDM table, licensing data. `DigitalProductId` and
  `DigitalProductId4` are left out.
- BitLocker: status and method only, never recovery keys or protectors.
- EK certificates: subject, issuer, serial number, validity and thumbprints, not the certificate
  itself.

A reading still identifies the machine exactly (serials, MACs, SIDs, the Windows device id), so
handle it like any other inventory data.

### How comparing works

Fields are compared by path, for example `smbios.system.serial` or
`network.adapters[0].hardware[0].BusNumber`. Values that change on their own, such as CPU load,
free memory, uptime or the last boot time, are shown but never counted as a difference. When the
two readings come from different schema versions, a field only the newer one collects is marked
`newer-probe-only` and is not counted either, so an old baseline still compares fairly.

---

## Install - recommended via uv

```bash
# One-shot run, no install
uvx fingerprint-machine@latest --help

# Install as a command line tool (isolated environment, added to PATH)
uv tool install fingerprint-machine
uv tool upgrade fingerprint-machine

# As a project dependency
uv pip install fingerprint-machine
```

For pip, pipx and source builds see [INSTALL.md](INSTALL.md).

### Supply-chain protection

This repository commits a `uv.lock`, which pins every package the project needs, transitive ones
included, to an exact version and to the hashes of its files. The `exclude-newer` setting under
`[tool.uv]` in `pyproject.toml` adds a cooldown: uv leaves any release younger than that out of the
lock. CI installs from the lock, so a hijacked release that is pulled again within the cooldown
never reaches our builds.

The installed package declares only lower bounds (`>=`) for its dependencies, so a plain
`pip install` takes the newest release of each dependency at that moment. To install with a
cooldown of your own, or to run the exact tree CI tests:

```bash
uv tool install --exclude-newer "7 days" fingerprint-machine
git clone https://github.com/bitranox/fingerprint-machine.git && cd fingerprint-machine && uv sync --locked && uv run fingerprint-machine --help
```

---

## Configuration and logging

The tool reads layered configuration (defaults, app, host, user, `.env`, environment) and logs
through [lib_log_rich](https://github.com/bitranox/lib_log_rich). Reading a machine needs neither;
see [CONFIG.md](CONFIG.md) to change log levels or targets. The `config`, `config-deploy`,
`config-generate-examples`, `info`, `logdemo` and `fail` commands belong to this part:

```bash
fingerprint-machine info                          # version and install details
fingerprint-machine config                        # the merged configuration
fingerprint-machine --set lib_log_rich.console_level=DEBUG collect
```

---

## Further documentation

- [Install guide](INSTALL.md)
- [Configuration](CONFIG.md)
- [Development handbook](DEVELOPMENT.md)
- [Contributor guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Module reference](docs/systemdesign/module_reference.md)
- [License](LICENSE)
