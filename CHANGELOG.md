# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.


## [Unreleased]

### Added

- `collect` and `check` run on Linux and read every section listed below; a value only root may
  read is recorded as needing root in its place.
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
- Windows `pci`: every PCI function under `Enum\PCI`, present or not, under the Linux key names
  (address `0000:bb:dd.f`, vendor, device, subsystem, revision, class code, driver, Device Serial
  Number where the instance id is the device's own serial), its parent and location paths, link
  speed and width and the other PCI device properties (through the configuration manager), the
  memory, I/O and IRQ ranges Windows allocated to it, its line-based and message-signaled
  interrupts and MSI settings; and system-wide the IRQ, I/O port, memory and DMA tables and the
  PCI buses.
- Windows `cpu.cpus`: every logical processor's registry description, in processor order.
- Windows `memory`: the totals, the page files and their settings, and the NUMA nodes with their
  processors.
- Windows `disks.scsi`: the SCSI device map port by port down to each logical unit, its INQUIRY
  answer decoded (vendor, model, rev, type) and its Device Identification page.
- Windows `devices`: the installed kernel drivers (`Win32_SystemDriver`) and every monitor's EDID
  decoded.
- Windows `security`: Secure Boot policy and servicing state, the TPM service's values (a cached
  TPM authorization value is withheld), BitLocker per volume and its policy (recovery material is
  never read, key protector ids never recorded), LSA protection, Kernel DMA Protection, Microsoft Defender,
  the firewall profiles, UAC, SmartScreen, Windows Update policy and results, Windows Hello for
  Business policy and the credential providers.
- Windows `security`: the values WMI answers only through methods, under each row's `methods`:
  per BitLocker volume the conversion status with its encryption percentage, the lock and
  protection status, the encryption method, the metadata version and its key protectors by type
  (`trusted platform module`, `numerical password` and so on); for the TPM its readiness,
  ownership, activation, the endorsement key's presence, the dictionary-attack parameters and the
  lockout counter. One refused method is one recorded error. Needs pwshpy 1.13.0.
- The `summary` has the same fields on Windows and Linux, so a Windows and a Linux reading of one
  machine compare field by field. System, BIOS, board and chassis values come from the decoded
  SMBIOS table and the CPU values from the `cpuid` section on both, falling back to WMI or to
  `/sys/class/dmi/id` and `/proc/cpuinfo` where those are missing; memory module sizes come from
  SMBIOS type 17. New fields: `system.bios_vendor`, `bios_date`, `board_manufacturer`,
  `board_product`, `board_serial`, `chassis_type`, `chassis_serial`; `cpu.vendor`, `hypervisor`,
  `hypervisors`; `pci_address` and `driver` per NIC and storage controller; `controller` per disk
  (Linux); an `os` group (name, version, hostname, machine id). The `windows` group is present on
  Linux with every field empty. The summary lists hardware only, on both OSes: on Linux devices
  under `/sys/devices/virtual` (loopback, bridges, loop and device-mapper disks) are left out, on
  Windows adapters that are no hardware interface (tunnel and VPN adapters) and storage
  controllers off the PCI bus (Storage Spaces), and optical drives on Linux, as Windows lists them
  apart from its disk drives. The full sections still list them. Storage controllers include
  AHCI on both OSes (Windows files it under its IDE controllers). NICs and storage controllers are
  in PCI address order on both, so the n-th entry of two readings of one machine is the same
  device. A Linux controller's `driver` is the SCSI driver it registers (`virtio_scsi`, not the
  generic `virtio-pci`); a Windows NIC's comes from the driver's path when the adapter names no
  driver file; a Windows disk's `model` is the SCSI INQUIRY product, as Linux reads it, and a
  Linux disk with no kernel WWID takes its VPD 0x83 logical-unit designator as `unique_id`, as
  Windows does.
- `compare` names where each field comes from in a `source` column (`smbios type 1 system uuid`,
  `pci device serial number`, `cpuid 0x40000000 hypervisor signature`, ...), in the text table and
  in the JSON rows, so a comparison of two machines reads as a list of values to adjust.
- `compare` treats more values as volatile, so two readings of one idle machine taken a minute
  apart compare without differences: interrupt counts, CPU clock readings, the `/proc/meminfo`
  usage counters, CPUID leaf 1 EBX (it carries the APIC id of the CPU that ran the read), PCI power
  state and status register, neighbour tables, kernel module reference counts, the boot id, IMA's
  measurement count, Defender signature ages and scan times, and page file usage.

### Changed

- `summary` values are written in one form on both OSes: a NIC `mac` in lower case with colons
  (`00:50:56:00:00:01`, was `005056000001`); `pci_serial` as the PCI Device Serial Number in the
  `lspci` form (`00-0c-29-ff-ff-00-00-01`, was the raw PnP instance id part), or empty when the
  device has none or reports all zeros; the system UUID and a disk's GPT GUID in upper case without braces; a disk's
  `unique_id` with its `naa.` or `eui.` prefix in lower case, as Linux writes it. The CPU name and
  `processor_id` come from CPUID first. `cpu.sockets`, `cores` and `logical_processors` are empty
  instead of 0 when the reading cannot tell them.

- Schema version 3. Compare marks fields only a schema 3 reading has as `newer-probe-only`
  against an older baseline.
- Windows `cpu.registry` (processor 0 only) is replaced by `cpu.cpus`, one entry per logical
  processor.
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
