# DHCP operational views

For implementation and testing, see the [developer guide](../dev/dhcp-operations.md).

All displays are available to operators and can be used with `run` in
configuration mode. They inspect runtime state without renewing clients,
restarting servers, or modifying leases.

```text
show dhcp-server leases
show dhcp-server pools
show dhcp-server listeners

show dhcp-server vrf BLUE leases
show dhcp-server vrf BLUE pools
show dhcp-server vrf BLUE listeners

show dhcp-server shared-network LAN leases
show dhcp-server vrf BLUE shared-network LAN pools

show dhcpv6-server leases
show dhcpv6-server pools
show dhcpv6-server listeners

show dhcpv6-server vrf BLUE shared-network LAN leases

show dhcp-client
show dhcp-client detail
show dhcp-client interface eth0
show dhcp-client interface eth0 detail
```

Use `Pool` in tables for the configured shared-network name. `Range` identifies
each allocation range within its subnet; ranges do not have separate names in
the configuration. Without a VRF filter, server views include every configured
instance. Pool filters may match the same pool name in several VRFs.

## Server data

The server's control socket supplies its applied configuration and socket
readiness. Lease records come from its memfile database, including cleanup
generations. Renewals replace earlier records; released, reclaimed and expired
leases are omitted. Declined leases remain visible and count toward utilization,
but are shown separately from assigned addresses. Reservations outside a dynamic
range appear in leases but do not consume that range's capacity. Usage is
`(assigned + declined) / total`; IPv6 totals use integer address counts.

Disabled servers are explicitly listed as omitted. An unavailable enabled server
or unreadable database produces an error, rather than a misleading empty table.
Leases belonging to a removed subnet retain their address and identifiers, with
`—` for the no-longer-known pool/subnet; a pool-scoped view excludes them.

Listener readiness comes from Kea, not merely from the existence of a process.
An enabled port without carrier reports `Waiting for carrier`. For DHCPv6 the
interface listener uses its link-local address; an explicitly selected unicast
address adds another row. Pool-scoped listener views require an explicit
or derived interface binding; an address-selected IPv4 shared network has no
exclusive listener, so use the server-wide listener view instead.

If leases change while the command is reading them and a consistent view cannot
be obtained, it asks you to retry.

## Client data

The client view uses netlinkd's owned interface definitions, current client
generation and lease, systemd state, and live kernel addresses/routes. A stale
generation or expired lease is never shown as bound. VLAN clients use their
full interface names, and VRF membership follows the live master hierarchy.

Detail output distinguishes the received gateway from the default route actually
installed with the expected table and distance. It shows received name servers
and whether this interface is selected as a system DNS source. A received domain
name is informational; it does not change system resolver policy.

Lease server, duration, and domain are captured on the next successful DHCP bind
or renewal after upgrading. Missing information displays `—`. udhcpc does not
expose its internal renewal/rebinding countdowns through the lease hook, so those
two fields display `—` rather than estimates.
