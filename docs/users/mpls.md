# MPLS and LDP

MPLS input interfaces belong under `protocols mpls`. LDP distributes labels;
your IGP or static routes still provide IP reachability to peers and destinations.
This release provides basic MPLS forwarding and dual-stack LDP in the default
VRF. VPN address families, BGP labeled-unicast and pseudowires are separate work.

## Basic configuration

```text
set protocols mpls interface eth2 interface eth3
set protocols ldp options router-id 192.0.2.1
set protocols ldp address-family ipv4 transport-address 192.0.2.1
set protocols ldp address-family ipv4 interface eth2
set protocols ldp address-family ipv4 interface eth3
set protocols ldp address-family ipv6 transport-address 2001:db8::1
set protocols ldp address-family ipv6 interface eth2
set protocols ldp address-family ipv6 interface eth3
```

Use reachable local addresses for the transports, commonly loopback addresses
advertised by the IGP. Peers must agree on their dual-stack transport preference.
FRR's default is IPv6; select IPv4 explicitly when needed:

```text
set protocols ldp options dual-stack transport-preference ipv4
```

Enabling MPLS creates a label table with 1,048,575 slots by default. The capacity
can be changed with `set protocols mpls label-table-size <16-1048575>`.
Reducing the table removes kernel entries outside the new capacity. Removing
`protocols mpls` clears its table and disables input on its configured interfaces;
remove LDP first or in the same commit.

MPLS input is reapplied when a selected interface is recreated. Removing an
interface from the MPLS list disables labeled input without deleting the link.
LDP interfaces must also appear in the MPLS interface list.

## Discovery and session settings

```text
set protocols ldp discovery hello interval 5 holdtime 15
set protocols ldp discovery targeted-hello interval 5 holdtime 45
set protocols ldp address-family ipv4 interface eth2 hello interval 3 holdtime 12
set protocols ldp address-family ipv4 targeted-neighbor 192.0.2.2
set protocols ldp address-family ipv4 discovery targeted-hello accept from-access-list LDP_PEERS
set protocols ldp neighbor 192.0.2.2 password 'shared-secret'
set protocols ldp neighbor 192.0.2.2 session-holdtime 30
set protocols ldp neighbor 192.0.2.2 ttl-security hops 2
```

The neighbor key is the IPv4 LSR ID, including for IPv6 sessions. Targeted-neighbor
and transport addresses use the selected address family. TTL security `disable`
and `hops` cannot be combined on one neighbor. Passwords are treated as secrets
in configuration output.

Hello timers inherit from the process to the address family to the interface.
An explicit timer overrides its parent even when it equals FRR's ordinary default.
Absent settings retain the native behavior. Other process settings include
`ordered-control`, `wait-for-sync`, `allow-broken-lsps` and dual-stack
`cisco-interop`. Interface `disable-establish-hello` disables FRR's accelerated
establishment hellos.

## Label policies

```text
set protocols ldp address-family ipv4 label local allocate host-routes
set protocols ldp address-family ipv4 label local advertise for-access-list LDP_PREFIXES to-access-list LDP_PEERS
set protocols ldp address-family ipv4 label local advertise explicit-null for-access-list LDP_PREFIXES
set protocols ldp address-family ipv4 label remote accept from-access-list LDP_PEERS for-access-list LDP_PREFIXES
```

Create the referenced policy access lists first or in the same commit. Prefix
filters use the selected address family. Peer filters always use IPv4 access
lists because they match LSR IDs. Allocation can select `host-routes` or an
`access-list`, but not both. Explicit-null requests a labeled final hop instead
of ordinary penultimate-hop popping.

## IGP synchronization

Synchronization prevents a point-to-point link from attracting transit traffic
before LDP is ready by temporarily raising its IGP metric. OSPFv2 and IS-IS
support it in the default VRF; OSPFv3 is not included.

```text
set protocols ospf ldp-sync hold-down 30
set protocols ospf interface eth2 ldp-sync hold-down 20
set protocols ospf interface eth3 ldp-sync disable

set protocols isis ldp-sync hold-down 30
set protocols isis interface eth2 ldp-sync hold-down 20
set protocols isis interface eth3 ldp-sync disable
```

The hold-down bounds how long the IGP waits. Removing an interface override
restores process inheritance. Use point-to-point IGP network types on these links.
OSPF interface hold-down `0` waits indefinitely. IS-IS interface hold-down `0`
inherits the process timer; its process hold-down `0` waits indefinitely.

## Operational commands

These commands pass through to FRR and retain its output and supported JSON forms:

```text
show mpls status
show mpls table
show mpls table 16000 json
show mpls fec
show mpls ldp discovery detail
show mpls ldp ipv6 interface
show mpls ldp neighbor
show mpls ldp neighbor 192.0.2.2 detail
show mpls ldp binding
show mpls ldp ipv6 binding 2001:db8::/64 detail
show mpls ldp capabilities
show mpls ldp igp-sync
show ip ospf mpls ldp-sync interface eth2
show isis mpls ldp-sync interface eth2
clear mpls ldp neighbor
clear mpls ldp neighbor 192.0.2.2
```

The optional address in `clear mpls ldp neighbor` is the transport address,
whereas the optional selector in `show mpls ldp neighbor` is the LSR ID.
