# Neighbor inspection

For implementation and testing, see the [developer guide](../dev/neighbor-operations.md).

Inspect the live ARP and IPv6 neighbor tables using consistent interface and VRF
selectors.

## Commands

```text
show arp
show arp interface eth0
show arp vrf BLUE

show ipv6 neighbors
show ipv6 neighbors interface eth0 vrf BLUE
```

## Output and filtering

Both commands use the same headered table: Address, MAC address, Interface, VRF,
and State. They report the live kernel neighbor table, including permanent,
incomplete and failed entries. Unresolved MAC addresses display as an em dash.
The IPv4 command shows ARP entries; the IPv6 command shows IPv6 neighbors.

Without a filter, all routing domains are included. Interface and VRF selectors
can be combined in either order; `vrf default` selects the default domain.
VRF membership follows kernel master relationships, including bridge and bond
masters. Unknown filters produce an error; a valid scope with no entries produces
an explicit empty-table message.

These read-only commands are available to all roles and work through `run` in
configuration mode. They do not initiate neighbor discovery or alter entries.
