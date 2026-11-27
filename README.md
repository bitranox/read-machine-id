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

`fingerprint-machine` reads what a Windows or Linux machine reports about itself and writes it out
as one JSON document: the SMBIOS table and the CPU's CPUID leaves, every PCI device with its
address, serial and interrupts, the network adapters with their driver settings, disk and
controller serials, and the TPM and Secure Boot state. On Windows it adds the Windows ids,
licensing and security settings; on Linux the kernel, modules, guest agents and disk encryption.
It can also compare two readings field by field, a Windows reading against a Linux one included.

What it is for:

- You move a machine to other hardware or another hypervisor and want to know which identity
  values changed: system UUID, serials, MAC addresses, NIC slot numbers, disk ids, the Windows
  device id. Any of them can break licensing, activation or a driver binding.
- You want one VM to look like another, say a VM that moved from VMware to Proxmox. Read both and
  compare: each differing row names where its value comes from (an SMBIOS field, a PCI serial, a
  CPUID leaf), so the diff is your list of values to adjust.
- You keep a baseline of a machine and check later that nothing drifted.
- You want a hardware and identity inventory from a script, as JSON rather than screen text.

It reads physical machines and VMs alike. Reading a machine needs Windows or Linux, and any other
OS is refused. Comparing two saved readings reads no machine, but the tool is built and tested on
Windows and Linux only.

---

## Quick start

### 1. Install uv

[uv](https://docs.astral.sh/uv/) runs the tool and fetches the Python it needs (3.15) by itself.

```bash
# Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Open a new terminal afterwards so `uv` and `uvx` are on the PATH.

### 2. Read the machine and save the reading

On Windows, from an elevated prompt ("Run as administrator"):

```powershell
uvx fingerprint-machine collect --out machine.json
```

On Linux, install it as a tool and run it as root:

```bash
uv tool install --compile-bytecode fingerprint-machine
sudo "$(command -v fingerprint-machine)" collect --out machine.json
```

`sudo uvx ...` does not work as well: sudo resets the PATH, so root finds no uv, and root's own uv
would download a second Python. `$(command -v ...)` hands sudo the full path of the installed tool.
`--compile-bytecode` compiles the tool's Python files at install time, as you; without it the first
run as root writes root-owned cache files into your tool environment, and a later
`uv tool upgrade` or `uv tool uninstall` fails on them. uv remembers the option for upgrades.

Either way it prints a summary table and saves the whole reading to `machine.json`. The file is
created like any file you write (0666 less your umask), so after a run under sudo you can still read
it; it belongs to root, so use `sudo rm` or `sudo chown "$USER" machine.json` if you want to
replace or delete it.

It runs without root or elevation too. What only root or an administrator may read is then
recorded as `{"error": "NeedsRootError: ... needs root (EACCES)"}` (Linux) or an access-denied error (Windows), and listed
under `skipped` in the `--json` output; the rest of the reading is unaffected. On Linux that is the
raw SMBIOS table with the system serial and UUID, the ACPI tables, the full PCI config space with
the Device Serial Numbers, a NIC's permanent MAC address, the I/O port and memory addresses, and
the TPM's EK certificate. On Windows it is mainly BitLocker and some other security sources.

### 3. Compare

```bash
# Compare two saved readings, e.g. the same VM on VMware and on Proxmox (reads no machine)
uvx fingerprint-machine compare vmware.json proxmox.json --diff-only

# Read the machine again and compare it with the saved reading in one step
uvx fingerprint-machine check machine.json --save after.json --diff-only                    # Windows, elevated
sudo "$(command -v fingerprint-machine)" check machine.json --save after.json --diff-only   # Linux
```

The comparison lists each differing field with both values and a `source` column naming what the
value is (`smbios type 1 system uuid`, `pci device serial number`, `cpuid 0x40000000 hypervisor
signature`).

---

## Commands

### `collect`

```text
fingerprint-machine collect [--section NAME ...] [--label TEXT] [--out FILE] [--no-cpuid] [--json | --json-bare]
```

Reads the machine. Without options it prints a summary table. `--json` prints the whole reading
inside an envelope, `--json-bare` prints only the reading. `--out` also saves the reading to a
file, `--label` names it (default: the computer name), and `--section` reads only the sections you
name, e.g. `--section network --section smbios`. `--no-cpuid` leaves out the `cpuid` section and
never runs the CPUID instruction: reading it needs a page of executable memory, which some
endpoint security products flag.

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

| Exit code | Meaning                                                                                  |
|-----------|------------------------------------------------------------------------------------------|
| 0         | done; for `compare` and `check`, no differences                                          |
| 1         | `compare` or `check` found differences                                                   |
| 2         | refused: neither Windows nor Linux (`collect`, `check`), or a file that is not a reading |

`--json` wraps the result as `{"ok": true, "command": ..., "data": ..., "skipped": [...]}`.
`skipped` lists each question a source could not answer, with the reason, for example a WMI class
the machine does not provide. A failure prints `{"ok": false, "command": ..., "error": {"type":
..., "message": ...}}`. `--json-bare` prints only the data, and still prints JSON when it fails.
Warnings go to standard error, so standard output can go straight into `jq` or a file.

---

## What a reading holds

A reading starts with `meta` (tool version, schema version, OS, time, label) and a `summary` of the
values people look for most. The summary has the same fields on Windows and on Linux, and writes each
hardware value in one form on both, so a Windows and a Linux reading of one machine compare field by
field:

```json
{
  "system": {
    "manufacturer": "Example Systems",
    "product": "Model X",
    "serial": "SER-0001",
    "uuid": "04030201-0605-0807-090A-0B0C0D0E0F10",
    "bios_vendor": "Example BIOS Vendor",
    "bios_version": "V1.2",
    "board_serial": "BOARD-0001",
    "chassis_type": 1
  },
  "cpu": { "vendor": "GenuineIntel", "processor_id": "BFEBFBFF000B0671", "hypervisor": "VMwareVMware" },
  "nics": [
    {
      "name": "Ethernet0",
      "mac": "00:50:56:00:00:01",
      "pci_serial": "00-0c-29-ff-ff-00-00-01",
      "pci_address": "0000:0b:00.0",
      "driver": "vmxnet3",
      "slot": 160
    }
  ],
  "disks": [{ "model": "Virtual disk", "serial": "DISK-0001", "unique_id": "naa.6000c29aaaaaaaaaaaaaaaaaaaaaaa" }],
  "os": { "name": "Windows 11 Pro", "hostname": "TESTBOX", "machine_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" },
  "windows": { "edition": "Professional", "build": "26100.1000", "partial_product_key": "JK7LZ" },
  "security": { "firmware_type": "UEFI", "secure_boot": 1, "tpm_version": "2.0", "vbs_status": 0 }
}
```

The values above are made up, and each group is shortened. The summary also has `memory` and
`scsi_controllers`; for a VMware PVSCSI controller it works out the SAS WWID from the controller's
PCI serial. System, BIOS, board and chassis values come from the SMBIOS table and CPU values from
CPUID on both OSes. A value the reading does not hold is `null`: the `windows` group on Linux, the
TPM manufacturer and VBS status on Linux, a disk's controller when it hangs on no PCI
controller. The OS facts (names,
interface numbers, `os`) differ between the two OSes by nature.

The full sections follow the summary. `--section` reads any of them alone:

| Section | What it holds |
|---|---|
| `smbios` | The raw SMBIOS table with every structure; BIOS, system, board, chassis, CPU, slots, memory, OEM strings and onboard devices decoded field by field. Linux adds the entry point and every `/sys/class/dmi/id` value |
| `acpi` | ACPI table headers (OEM ids), and whether an MSDM table holds a product key |
| `platform` | Windows: BIOS, computer system (domain or workgroup included), product, baseboard and enclosure from WMI, and the BIOS and system values in the registry. Linux: kernel and command line, os-release, hostname, machine id, D-Bus machine id, boot id, DMI modalias, container and hypervisor detection, clock source |
| `cpu` | Windows: processors and caches from WMI, and every logical processor's registry description. Linux: `/proc/cpuinfo` per CPU, topology, caches, frequency, SMT, vulnerabilities |
| `cpuid` | The CPU's CPUID leaves (Windows and Linux): vendor, family, model, stepping, brand, feature flags, every hypervisor signature (`0x40000000` and the later bases), and each leaf read as raw registers |
| `memory` | Windows: memory modules and arrays, the totals, page files and their settings, NUMA nodes with their processors. Linux: meminfo, memory blocks, NUMA nodes, huge pages |
| `disks` | Windows: disks, partitions, volumes, initiator ports with serials and GUIDs, and the SCSI device map with each unit's INQUIRY and VPD 0x83 ids. Linux: each block device (VPD ids, queue, partitions, udev ids), NVMe, SCSI, FC and SAS controllers, PCI ids |
| `network` | Windows: PCI location, driver settings, offloads, RSS, power, bindings, class key, addresses, routes, DNS. Linux: sysfs, ethtool (features, rings, link modes), netlink addresses, routes, neighbours |
| `pci` | Every PCI function with its address, ids, class, driver, Device Serial Number, parent and location paths, link speed and width, allocated ranges and interrupts (line-based and message-signaled); the system's interrupt, I/O port, memory and DMA tables |
| `hardware` | Windows: SCSI, IDE and USB controllers, CD drives, keyboards, mice, sound, monitors, serial ports, video |
| `devices` | Windows: every device instance under the registry's `Enum` key, present or not, with hardware ids, location and driver; the installed kernel drivers; each monitor's EDID. Linux: every device on the PCI, USB, virtio, VMBus, SCSI, platform and ACPI buses and every input device, with modalias and driver; the loaded kernel modules; each display's EDID |
| `windows` | Windows: operating system, the `CurrentVersion` key, device id, MachineGuid, machine SID, TCP/IP names, time zone, licensing, hotfixes, cloud join |
| `security` | Windows: TPM (WMI, TBS, the TPM service's values), cached EK certificates (public fields only), Secure Boot state, policy and servicing, Device Guard and VBS, BitLocker per volume (lock state, encryption percentage, key protector types) and its policy, TPM readiness and lockout state, LSA protection, Kernel DMA Protection, Defender, firewall profiles, UAC, SmartScreen, Windows Update policy and results, Windows Hello policy, credential providers. Linux: firmware type, Secure Boot and MOK state, TPM, EK certificates (public fields only), kernel lockdown, LSMs, SELinux, AppArmor, IMA, device-mapper volumes with the LUKS header's public fields, firewall |
| `services` | Windows: every service with its state and start mode. Linux: whether each guest agent (open-vm-tools, qemu-guest-agent, Hyper-V daemons, waagent, cloud-init, spice-vdagent, VirtualBox and Xen guest tools) is installed, enabled and running; the cloud-init instance id |

A question that cannot be answered (a missing WMI class, access denied) is recorded as
`{"error": "..."}` in its place and listed under `skipped`, and the reading goes on.

### What it never writes

- Product keys are cut to their last five characters wherever they turn up: the
  `OA3xOriginalProductKey` value, the ACPI MSDM table, licensing data. `DigitalProductId` and
  `DigitalProductId4` are left out.
- BitLocker: status, percentage, method and the TYPES of the key protectors, never a recovery key
  or a protector id.
- TPM authorization values Windows may have cached in the registry are replaced by a placeholder.
- EK certificates: subject, issuer, serial number, validity and thumbprints, not the certificate
  itself.
- LUKS (Linux): version, UUID, label, cipher and data segments from the header, never a key
  slot, the master key digest, the salt or a LUKS2 token.

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

It needs Python 3.15 or newer, the version CI tests. uv fetches a suitable Python by itself when
none is installed.

```bash
# One-shot run, no install
uvx fingerprint-machine@latest --help

# Install as a command line tool (isolated environment, added to PATH; precompiled, so a run
# under sudo writes nothing into it)
uv tool install --compile-bytecode fingerprint-machine
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
