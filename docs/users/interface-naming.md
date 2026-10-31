# Persistent Ethernet names

For implementation and testing, see the [developer guide](../dev/interface-naming.md).

nVyR assigns physical wired Ethernet ports `eth0`, `eth1`, … before netlinkd or
configd applies interface configuration. PCI/virtio NICs in virtual machines are
included. Wireless devices and logical links such as dummy, veth, bridges and VLANs
keep their own naming rules.

## Port identity and persistence

The assignment database is `/var/lib/nvyr/interface-names.json`. It is separate from
the saved router configuration: `save`, configuration deletion and rollback do not
change port assignments. Back it up with the router state and preserve it when
upgrading the same machine. Copying only the saved configuration does not preserve port names.
An ephemeral live ISO needs persistent storage for this database to survive reboot;
without persistence it can only reconstruct assignments from the currently present
hardware. Installed images retain it through `/config/.nvyr`; image upgrades copy it
with the other private daemon state.

Compatible replacement hardware in the same location inherits the saved name even
when its MAC changes. Multiple ports remain distinct. A missing interface retains
its reservation; a newly discovered location receives the lowest available `ethN`
without moving existing assignments. The first inventory is allocated in sorted
identity order. Names are durably written before the live interfaces are renamed.

Firmware changes, changed PCI bridges/function layouts, moving a USB hub, or drivers
reporting different port identifiers can change physical identity. USB2 and USB3
root hubs are deliberately kept distinct: some controllers expose the same external
receptacle through different root hubs when adapter speed changes. Linux does not
always supply enough information to equate those locations safely. Such topology
changes can require an administrator to reconcile the database during maintenance.
Ambiguous identities are rejected instead of merging ports or falling back to MACs.

## Administration and failures

Use `show interfaces` and `show system services` to inspect port names and service
health. Host-level mapping maintenance requires dev-admin access or recovery media.

A corrupt database, duplicated physical identity or reserved name occupied by an
unmanaged link is an error. Startup blocks configuration instead of guessing a new
mapping. During hotplug the affected port stays unconfigured and errors are logged;
already configured ports remain running. The coordinator retries after conflicts
are corrected. Do not delete the database to repair a conflict: that discards absent
port reservations and may change which device receives a saved configuration.

Process failures also retry automatically with increasing delays capped at 30
seconds. Ordered netlinkd and configd startup jobs remain pending until naming
reports readiness, rather than requiring a manual start after naming recovers.
A naming crash after readiness leaves healthy consumers running. Intentional
service stops remain effective. See [daemon recovery](../dev/initialization.md#daemon-recovery).

For a persistent naming conflict, use a local console and consult the
[maintenance procedure](../dev/interface-naming.md#mapping-maintenance). Do not
change physical port names while their saved configuration is being applied.
