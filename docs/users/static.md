# Static routing

For implementation and testing, see the [developer guide](../dev/static.md).

Configure IPv4 and IPv6 static routes in the default routing instance or a named
VRF. FRR selects active routes and installs them through Zebra. For the shared
reload, ownership and recovery implementation, see [FRR integration](../dev/frr.md).

## Configuration

```text
set protocols static route 192.0.2.0/24 next-hop 192.0.2.1
set protocols static route 192.0.2.0/24 next-hop 192.0.2.1 distance 10
set protocols static route 192.0.2.0/24 next-hop 192.0.2.1 interface eth0
set protocols static route 192.0.2.0/24 next-hop 192.0.2.1 metric 100
set protocols static route 192.0.2.0/24 next-hop 192.0.2.1 weight 20
set protocols static route 192.0.2.0/24 next-hop 192.0.2.1 tag 123
set protocols static route 192.0.2.0/24 blackhole distance 254

set protocols static route 198.51.100.0/24 interface eth1
set protocols static route 203.0.113.0/24 reject

set protocols static route6 2001:db8:100::/64 next-hop 2001:db8::1
set protocols static route6 2001:db8:100::/64 next-hop fe80::1 interface eth0

set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 next-hop 2001:db8::2

commit
save
```

## Forwarding and discard paths

`route` and `route6` are anchor-capable network-prefix tags. `next-hop` remains an
address tag; its `interface` is a single-value leaf, so changing it replaces the
interface associated with that address. An `interface` tag directly under the
route provides interface-only forwarding. No numbered path objects are used.

Interface names `Null0`, `blackhole`, and `reject` are rejected at CLI entry and
when loading configuration, regardless of capitalization. FRR treats those names
as discard actions; use the dedicated `blackhole` or `reject` nodes instead.

Both forwarding forms support `distance` (1–255, direct default 1), `metric`
(0–4294967295, direct default 0), `weight` (1–65535), `tag` (1–4294967295),
`vrf`, `description`, and `disable`. Address next hops additionally support
`interface` and valueless `onlink`; onlink requires an interface. Defaults remain
absent from explicit/saved configuration. Equal distance and metric group next
hops for ECMP; different preferences provide floating alternatives. Weight
controls the relative traffic distribution within a group, not preference.
FRR chooses the maximum tag among next hops in one ECMP group. Distance 255
retains FRR's non-installable administrative-distance behavior.

`blackhole` silently discards traffic; `reject` produces an ICMP unreachable.
Both are nodes with distance, metric, tag, description and disable children.
They share one FRR identity, so only one may be enabled per destination/source
entry. A discard path can coexist with forwarding paths only at a different
distance/metric preference, for example a distance-254 fallback blackhole.

## Address families and source-specific routes

IPv4 destinations accept IPv4 or IPv6 next hops (`inet-address`); IPv6 destinations
accept IPv6 next hops (`ipv6-address`). IPv6 link-local next hops require an
interface. The generic `network` validator requires a prefix length and zero host
bits. IPv6 source-specific routing uses `route6 <destination> source-specific from
<source-prefix>` and reuses all forwarding/discard options. Multiple source
prefixes and an ordinary destination route may coexist. An enabled `from ::/0`
entry cannot coexist with an enabled ordinary route for the same destination,
because they would produce the same FRR route key. Equivalent IP spellings that
would produce duplicate enabled forwarding identities are also rejected.

## Disabling and validating routes

Descriptions are nVyR metadata and never sent to FRR. `disable` on a destination
suppresses the entire subtree; disable on a source-specific entry suppresses that
entry; disable on a next hop, interface, blackhole or reject suppresses that path.
Disabled entries retain their configuration and references and skip operational
verification. Schema value validation still applies. Each enabled route needs at
least one enabled forwarding/discard path, or enabled source-specific routes.
Each enabled source-specific entry needs at least one enabled path. A disabled
gateway collection is fine when another forwarding or discard option serves the
same entry; there is no requirement to enable one path of every configured type.
To withdraw everything, disable or delete the prefix. Deleting the last child
preserves its parent as usual; commit rejects incomplete enabled entries.

Interface and next-hop VRF references protect the referenced configuration from
deletion, including while a route is disabled. FRR determines reachability and
whether a route is eligible for installation.

Multicast, BFD, MPLS, SR-TE, SRv6 and explicit table overrides are outside this
implementation. See [static routing displays](static-routing-operations.md) for
the available operational commands.

A next hop cannot equal a local address in its resolution VRF, even on a down
interface. An address local only to another VRF is allowed. An unreachable next
hop is accepted as configuration but may remain inactive.

## VRF routing

```text
set vrf name BLUE table 100

set vrf name BLUE protocols static route 192.0.2.0/24 next-hop 198.51.100.1
set vrf name BLUE protocols static route6 2001:db8::/32 next-hop 2001:db8::1

set vrf name BLUE protocols static route 192.0.2.0/24 next-hop 198.51.100.1 vrf RED
```

The route's VRF determines where the route is installed. The `vrf` leaf under a
next hop selects the VRF used to resolve that next hop; `vrf default` selects the
default routing instance. These are separate choices. Create the referenced VRFs
and their interfaces as needed; Linux VRF management is described in
[interfaces](interfaces.md).

All registered static-routing instances apply together through one shared reload.
Removing static configuration from a VRF withdraws its routes while retaining
FRR's empty static instance. See [static adapter and VRF retention](../dev/frr.md#static-adapter-and-vrf-retention)
for the ownership and removal behavior.

## Operational commands

```text
show ip route static
show ipv6 route static

show ip route vrf BLUE static
show ipv6 route vrf BLUE static

show static routes
show static routes vrf BLUE
```

The route-table commands show static routes known to Zebra. `show static routes`
shows staticd's configured routes and next-hop status, including routes that are
not installed. In configuration mode, prefix operational commands with `run`.
See [static routing displays](static-routing-operations.md) for filtering, summaries
and the internal structured-output interface.
