# Linux bonding

The bond configuration script gathers interface and VRF configuration, verifies
membership and mode-specific restrictions, and generates one netlinkd owner
transaction for the bonds and their VLAN children. The member's own interface
script still owns its administrative state. The bond owns attachment, port queue
and priority. Bond priority precedes bridge configuration so a bridge may use
the bond itself as a port.

`bond_config.py` maps CLI settings to Linux UAPI values. `bond_netlink.py`
extends the packaged pyroute2 message tables for the shipping kernel and uses
netlinkd's existing socket. Kernel restrictions determine the order of updates:
detach members for a mode or failover MAC change, lower the bond for settings
that require it, and select the primary after attaching ports. Compare observed
attributes before writing; repeated audits must not flap links.

The operational script reads the bonding driver's report, including both sides
of the LACP exchange. The package configures the bonding module with
`max_bonds=0` so loading the driver does not create an unowned bond0.

Use the bond smoketests for native configuration, the shared functional interface
topology for forwarding after failover, and the acceptance bond for boot recovery.
See the [operator examples](../users/bonds.md).
