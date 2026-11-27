# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.


## [Unreleased]

### Added

- `collect` and `check` run on Linux. This version reads the `cpuid` section there; a section not
  yet read on Linux is recorded as an error in its place and listed under `skipped`.
- A `cpuid` section on Windows and Linux: vendor, family, model, stepping, brand string, the
  feature flags of leaves 1, 7 and 0x80000001 (named as `/proc/cpuinfo` names them, unnamed bits
  as `bit<N>`), the hypervisor-present bit, every hypervisor signature found by scanning the
  hypervisor bases from 0x40000000 (a KVM guest with Hyper-V enlightenments shows both "Microsoft
  Hv" and "KVMKVMKVM"), and every leaf read as raw registers. A leaf that cannot be read is one
  recorded error; the rest is still read.
- `collect --no-cpuid` leaves the `cpuid` section out and never maps the executable page CPUID
  needs.
- `meta.os` records `windows` or `linux`.
- Linux `smbios`: the raw DMI table decoded as on Windows (same `smbios.system` shape) with the
  version from its entry point, both read as root; `dmi_id` holds every `/sys/class/dmi/id`
  attribute, readable unprivileged except the serials and the UUID.
- Linux `acpi`: the header of every table under `/sys/firmware/acpi/tables` (runtime-loaded ones
  under `dynamic/` too), read as root; MSDM only as present with the key masked to its last five.
- Linux `platform`: kernel release, version and command line, os-release, hostname, machine id
  (systemd and D-Bus), boot id, DMI modalias, container type, `/sys/hypervisor`, the clock source,
  and a `virtualization` verdict like `systemd-detect-virt`'s, decided from CPUID and DMI without
  running anything (with `--no-cpuid` from DMI alone).
- Linux `cpu`: `/proc/cpuinfo` per logical CPU (flags and bugs as lists), each CPU's topology,
  caches and frequency limits, the system CPU masks and SMT state, every vulnerability verdict.
- Linux `memory`: `/proc/meminfo` in bytes, memory blocks, NUMA nodes, huge page pools and the
  transparent huge page mode.
- Linux `security`: firmware type and Secure Boot under the Windows key names, shim MOK state, the
  TPM and its EK certificates (read from the TPM through `/dev/tpmrm0` as root, public fields
  only), kernel lockdown, LSMs, SELinux, AppArmor profile counts per mode, IMA, device-mapper
  volumes (dm-crypt with the LUKS version, cipher and UUID read as root, never a key slot; LVM),
  and the loaded netfilter modules.
- Linux `services`: the guest agents (open-vm-tools, qemu-guest-agent, Hyper-V daemons, waagent,
  cloud-init, spice, VirtualBox, Xen, Google and Amazon agents) installed, enabled and running,
  and cloud-init's instance id.
- Linux `pci`: every PCI device with its address, its parent chain from the root bus
  (so the reading is a topology), ids, class, driver, IOMMU group, NUMA node, ACPI path, slot, bus
  numbers, resource ranges, link speed and width, power state, the configuration space header and
  (as root) the capability walk with the Device Serial Number, PCI Express port type, MSI, MSI-X,
  AER and SR-IOV; per device its legacy IRQ and pin, MSI vectors, `/proc/interrupts` rows and CPU
  affinity; and system-wide the interrupt descriptors, named interrupt counters, `/proc/ioports`,
  `/proc/iomem` and DMA channels. Values only root can read are recorded as needing root.
- Linux `devices`: every device on the pci, usb, virtio, vmbus, scsi, acpi and
  platform buses and every input device, with modalias, driver and the bus's id files; the loaded
  kernel modules; and the EDID of every display connector (manufacturer, product, serial, name,
  date).
- Linux `disks`: every block device with its size, queue limits, I/O scheduler, the identity its
  device reports (vendor, model, serial, WWID, VPD pages 0x80 and 0x83 decoded), the PCI controller
  and bridges above it, its partitions and what udev recorded for them (filesystem UUID and label,
  partition UUID); NVMe controllers and namespaces, SCSI hosts, Fibre Channel and SAS ports, each
  controller's PCI ids and Device Serial Number (root), and for a VMware PVSCSI controller the
  `sas_wwid` that serial encodes.
- Linux `network`: per interface the sysfs values, the PCI function behind it with its serial,
  every ethtool answer (driver, burned-in address, each offload feature, link modes, rings,
  channels, coalescing, pause, wake-on-LAN as root) and the rtnetlink link, addresses, routes and
  neighbours joined to it by interface index; rows naming no interface under `unmatched`; DNS from
  `resolv.conf` and systemd-resolved. A netlink table is kept to 10000 rows.

### Changed

- Schema version 3. Compare marks fields only a schema 3 reading has as `newer-probe-only`
  against an older baseline.
- `collect` and `check` refuse with exit 2 only on an OS that is neither Windows nor Linux.
- Python 3.15 or newer is required (3.10 to 3.14 are dropped); CI tests 3.15. orjson is
  a plain dependency that parses `--set` values on every interpreter; the `orjson` extra and the
  standard-library fallback are gone. The devcontainer uses the Python 3.15 image.
- CI tests on Windows and Linux only; macOS is no longer tested. The package classifiers name
  Windows and Linux instead of "OS Independent".

## [0.1.0] - 2026-11-27

### Added

- `collect` reads a Windows machine into one JSON reading: the raw SMBIOS table with every
  structure kept and the identity-bearing types decoded (slots, onboard devices, memory arrays and
  mappings included), ACPI table headers and the MSDM key's presence, firmware and computer-system
  data, CPU and memory, disks with serials and GUIDs, each network adapter with its PCI location,
  advanced driver settings, offloads, class key, addresses and routes, every device under the
  registry's `Enum` key, the Windows ids (product id, device id, MachineGuid, machine SID) and
  licensing, the TPM through WMI and TBS, cached EK certificates, Secure Boot, Device Guard and
  BitLocker status, and every service. A `summary` block comes first.
- `compare` compares two saved readings field by field; `check` reads this machine and compares
  it with a baseline. Counters that change on their own are shown but not scored, and a field only
  a newer schema collects is marked `newer-probe-only`.
- `--out` saves a reading or comparison, `check --save` keeps the fresh reading. `--json` prints an
  `{ok, command, data, skipped}` envelope, `--json-bare` prints only the data and stays JSON on
  failure. Exit codes: 0 done, 1 differences found, 2 refused.
- Each question is read on its own: one a source cannot answer is recorded as an error at its place
  and listed under `skipped`, and the rest of the reading goes on. A registry key that exists only
  when a feature is on (cloud join, the EK certificate store) reads as empty when absent.
- Product keys are cut to their last five characters wherever they appear; `DigitalProductId` and
  `DigitalProductId4` are withheld; EK certificates are reduced to their public fields.
- A VMware PVSCSI controller's SAS WWID is worked out from its PCI serial in the summary.
