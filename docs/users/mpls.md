# MPLS and LDP

MPLS input interfaces belong under `protocols mpls`. LDP distributes labels;
your IGP or static routes still provide IP reachability to peers and destinations.
MPLS forwarding and dual-stack LDP operate in the default VRF. BGP labeled-unicast
is also available; VPN address families and Segment Routing are separate work.

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

Enabling MPLS creates a label table with 1,048,575 slots. This capacity is fixed.
Removing `protocols mpls` clears its table and disables input on its configured interfaces;
remove LDP first or in the same commit.

MPLS input is reapplied when a selected interface is recreated. Removing an
interface from the MPLS list disables labeled input without deleting the link.
LDP interfaces must also appear in the MPLS interface list.

## Label allocation

The fixed dynamic label range is **100000–1048574**. FRR allocates chunks from
this range as protocols need them; defining the range does not allocate every
label. Labels **16–99999** remain outside dynamic allocation for static labels
and a future Segment Routing global block. This does not configure an SRGB today.

```text
show debugging label-table
show debugging label-table json
```

Zebra loads this range before LDP starts, so even LDP's first reserved chunk uses
the fixed range. Neither the range nor the table capacity is configurable.
Static incoming labels use **16–99999**. Outgoing labels belong to the next router
and do not share that restriction.

## Static label forwarding

Use `lsp` for an incoming MPLS label and static IP routes for label imposition:

```text
set protocols mpls lsp 16000 description 'Transit to PE2' next-hop 192.0.2.2 outgoing-label 17000
set protocols mpls lsp 16001 next-hop 192.0.2.2 outgoing-label implicit-null
set protocols mpls lsp 16002 next-hop 2001:db8::2 outgoing-label explicit-null
set protocols static route 198.51.100.0/24 next-hop 192.0.2.2 label 17000/18000
set protocols static route6 2001:db8:100::/64 next-hop 2001:db8::2 label 17000/18002
```

A numeric outgoing label swaps the incoming label. `implicit-null` pops it;
`explicit-null` sends the appropriate explicit-null label for the next-hop address
family. Multiple next hops can be configured for one incoming label. Static LSP
next hops must be reachable; IPv6 link-local next hops are not supported by FRR's
static LSP command because it cannot include an interface scope.

Static IP routes accept slash-separated stacks, outermost label first, with up to
16 labels. The final label may be `0` for IPv4 explicit-null or `2` for IPv6
explicit-null. Configure the receiving router to handle the labels you send.

## Recursive labeled-unicast and TTL

```text
set protocols mpls fec nexthop-resolution
set protocols mpls disable-ttl-propagation
set protocols mpls default-ttl 64
```

FEC next-hop resolution allows FRR to resolve a labeled-unicast route through an
underlying labeled route to its next hop. It does not create that transport route:
the IGP/LDP or static transport must already provide it.

Use penultimate-hop popping for transport to an explicit-null LU endpoint. In the
Linux forwarding tests, a recursive stack containing two explicit-null labels
(`0/0` or `2/2`) was installed but dropped on receipt. The separate direct LDP
and LU paths with one explicit-null label worked normally.

By default, Linux propagates IP TTL/hop-limit into the MPLS label stack (uniform
mode). `disable-ttl-propagation` selects pipe behavior, using `default-ttl` for
imposed labels instead. Its default is 255. Removing these settings restores the
native defaults.

## MTU

Each MPLS label adds four bytes. A 1500-byte IP packet with two labels needs a
1508-byte link MTU along the part of the path carrying both labels. Configure the
interfaces and intervening switches accordingly; enabling MPLS does not raise MTU
automatically. Check the maximum stack depth along the whole path, including any
future VPN or Segment Routing labels.

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
