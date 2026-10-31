# Persistent Ethernet names: implementation and maintenance

For configuration and command usage, see the [user guide](../users/interface-naming.md).

## Startup and hotplug

`nvyr-interface-naming.service` is a small naming coordinator. **nvyr-netlinkd owns link state and direct Netlink operations, with udhcpc
providing DHCPv4 negotiation.** The coordinator only allocates
names, performs Netlink renames and hands devices to netlinkd; it does not generate
addresses, routes or interface profiles.

1. `70-nvyr-ethernet.rules` marks physical Ethernet links as owned by the naming
   coordinator using `ID_NET_MANAGED_BY`. The Netlink daemon waits for a matching naming-ready record.
   On device addition, udev moves the kernel name into the temporary `nvn<ifindex>`
   namespace. `10-nvyr-ethernet.link` disables Debian's competing name/MAC policies.
2. The coordinator waits for udev initialization, checks the assignment database and
   occupied names, and moves conflicting ports through temporary names before final
   renaming. Link operations use ifindices. It does not cycle healthy named links.
3. After the final name is installed, a runtime record in `/run/nvyr-naming/ready/`
   permits a udev change event to release that exact device/name/index to netlinkd.
4. The service announces readiness after the handoff. Both netlinkd and configd
   require successful startup. Ethernet verification and application also reject
   physical links still awaiting naming.

Physical udev events trigger reconciliation, coalesced over a bounded 200 ms
window. Virtual-link events are discarded using their event path, without reading
their sysfs attributes or udev properties. Healthy naming waits up to 60 seconds
between safety inventories; pending handoffs and rename conflicts retry every
second. Notification overflow requests an immediate inventory. Inventories read
class symlinks and construct udev devices only for physical links, and startup
coldplug triggers only physical devices rather than every dummy/virtual interface.
Discovery and handoff write `change` to the device's open sysfs `uevent` file.
That descriptor remains tied to the same device if udev renames it. A rename or
removal before the file opens causes a fresh discovery pass within the startup
deadline; a failed trigger never permits an early readiness announcement.
Successful coldplug is not repeated while waiting for udev handoff.

Absent configured ports can be recovered when they reappear:
netlinkd's desired mappings use the final name. The runtime records survive coordinator
restart but not reboot; the persistent allocation is the authoritative mapping.

The udev ownership marker becomes `io.nvyr.Netlink` after naming; it never hands
physical devices to systemd-networkd. The daemon checks the naming-ready record
before touching a port. Existing [udev link policies](https://www.freedesktop.org/software/systemd/man/257/systemd.link.html)
remain responsible for suppressing competing automatic renaming.
The temporary namespace addresses the
[kernel/userspace `ethN` race](https://github.com/systemd/systemd/blob/main/docs/PREDICTABLE_INTERFACE_NAMES.md).
Do not run another network manager, custom naming rules or independent renaming
commands on nVyR physical ports.

## Tests

`test_interface_names.py` covers physical identity, replacement, reversed discovery,
name reservations, collisions, failed persistence and handoff validation.
`test_interface_names_live.py` exercises real Netlink swaps and replacement inside
an isolated network namespace in the disposable privileged test container, and
checks that naming failure prevents both netlinkd and configd startup.

`test_interface_naming_coldplug.py` covers fresh discovery after renames/removal,
descriptor identity, bounded failure reporting and readiness ordering.
`test_interface_naming_coldplug_live.py` reproduces renames before and after opening
the real sysfs event file, plus removal during discovery. These opt-in tests use
private network and mount namespaces with disposable links; set
`NVYR_RECOVERY_TEST=1` when running them as root on a Linux test system. The naming
process must reach readiness without requiring a service restart.

Integration was also exercised in a QEMU VM using the nVyR live image with the new
naming components installed and an ext4 state disk retained across two boots. This
covered e1000-to-virtio replacement in the same PCI slot, changed MACs and discovery
order, USB unplug/replacement at the same connector (including changed USB interface
number), simultaneous USB/PCI hotplug, netlinkd address application, and reserving
the name of a missing port while allocating a new port. Physical
topology depends on firmware and driver reporting; actual target hardware should
also be qualified across cold boots and adapter replacements.

## Physical identity selection

Identity uses udev's physical topology, in this order:

- USB: controller and physical connector/hub path from `ID_PATH_WITH_USB_REVISION`
  (falling back to `ID_PATH`), plus the device's
  port number. USB serial numbers, MAC addresses and USB configuration/interface
  numbers are not used.
- Other buses: firmware onboard index or hotplug slot identity, including the
  function/port distinction reported by udev.
- Otherwise: udev's attachment path and physical port identifier, or physical sysfs
  ancestry when no path is exported. Unstable virtio enumeration numbers are removed.

## Naming diagnostics

Inspect the mapping and status with:

```sh
sudo cat /var/lib/nvyr/interface-names.json

systemctl status nvyr-interface-naming.service
journalctl -u nvyr-interface-naming.service -b

udevadm info /sys/class/net/eth0
ip -brief link
```

The service also accepts `--debug` for physical-event diagnostics. Routine idle
scans and ignored virtual events are silent at the default INFO level.

## Mapping maintenance

For manual mapping maintenance, use a local console, stop configd, netlinkd and the
naming coordinator, back up the database, preserve unique `ethN` values, then reboot.
Restarting the naming service alone intentionally refuses to rename a port already
handed to netlinkd under the wrong name. Package installation reloads definitions
but does not take over or rename an existing host's active interfaces; activate this
router-wide policy during a maintenance reboot. The ISO enables it automatically.
