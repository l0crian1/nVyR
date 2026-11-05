# OSPFv2 and OSPFv3

Use `protocols ospf` for IPv4 and `protocols ospfv3` for IPv6. Both also work
under `vrf name <name> protocols`. OSPFv3 uses IPv6 link-local addresses for
adjacencies; enable IPv6 on its participating interfaces.

Area IDs accept decimal and dotted decimal notation. `0` and `0.0.0.0` identify
the same backbone area. Define each area using one spelling.

## A dual-stack point-to-point link

Configure the link's addresses first, then enable each routing protocol. The
neighbor must use a different router ID and matching area, network type,
authentication, and hello/dead timers.

```text
set interfaces ethernet eth1 address 192.0.2.1/30
set interfaces ethernet eth1 address 2001:db8:1::1/64

set protocols ospf options router-id 192.0.2.1
set protocols ospf interface eth1 area 0 network point-to-point
set protocols ospf interface eth1 cost 10 hello-interval 10 dead-interval 40

set protocols ospfv3 options router-id 192.0.2.1
set protocols ospfv3 interface eth1 area 0 network point-to-point
set protocols ospfv3 interface eth1 cost 10 hello-interval 10 dead-interval 40
```

Use `interface <name> passive` to advertise a connected network without forming
adjacencies on that interface. `passive disable` explicitly selects active
operation. OSPFv2 also supports `passive-default` with per-interface exceptions.

```text
set protocols ospf passive-default
set protocols ospf interface eth1 passive disable
set protocols ospf interface eth2 area 0 passive

set protocols ospfv3 interface eth2 area 0 passive
```

## Areas, summaries and policies

Normal areas need no type setting. A non-backbone area can instead be `stub` or
`nssa`; `no-summary` suppresses ordinary inter-area summaries. An area range
summarizes routes at the ABR, while `summary-address` summarizes redistributed
external routes. `no-advertise` suppresses the selected range.

```text
set protocols ospf area 10 stub no-summary
set protocols ospf area 10 default-cost 20
set protocols ospf area 10 range 10.10.0.0/16 cost 50

set protocols ospfv3 area 0.0.0.10 nssa no-summary
set protocols ospfv3 area 0.0.0.10 nssa default-information originate metric 20 metric-type 1
set protocols ospfv3 area 0.0.0.10 range 2001:db8:10::/48 cost 50
```

OSPFv2 can select participating interfaces with `area <id> network <prefix>`,
or use the explicit `interface <name> area <id>` form shown above. The explicit
form is available in both families.

Both protocols support redistribution from connected, local, static, kernel,
and BGP routes. OSPFv2 additionally supports `redistribute table <id>` and
`redistribute table-direct <id>`. Attach a route-map to restrict and modify
redistribution. Type 1 adds the internal path cost; type 2 compares the external
metric before the internal path cost.

```text
set policy prefix-list ipv4 OSPF_EXPORT rule 10 action permit prefix 198.51.100.0/24
set policy route-map OSPF_EXPORT rule 10 action permit match ipv4 prefix-list OSPF_EXPORT
set policy route-map OSPF_EXPORT rule 10 set metric 30 metric-type type-1 tag 100

set protocols ospf redistribute static route-map OSPF_EXPORT
```

Use `area <id> filter-list in|out <prefix-list>` for inter-area prefix filtering.
The referenced list must match the protocol's address family. Area import/export
access-lists are also available. OSPFv2 has per-source export distribute-lists;
OSPFv3 has an interface `advertise-prefix-list`.

## Authentication and key rotation

Reusable keychains work with both protocols. A key needs an algorithm and secret.
OSPFv2 key IDs are 1–255; OSPFv3 key IDs are 1–65535. Omit lifetimes for keys
that remain valid indefinitely. Lifetime timestamps use the router's configured
time zone, with fixed `YYYY-MM-DDTHH:MM:SS` input. A lifetime needs a start and
exactly one of `end`, `duration` (seconds), or `infinite`.

```text
set policy key-chain UPLINK key 1 algorithm hmac-sha-256 secret replace-this-secret
set policy key-chain UPLINK key 1 accept-lifetime start 2026-01-01T00:00:00 infinite
set policy key-chain UPLINK key 1 send-lifetime start 2026-01-01T00:00:00 infinite

set protocols ospf interface eth1 authentication key-chain UPLINK
set protocols ospfv3 interface eth1 authentication key-chain UPLINK
```

Coordinate keys and overlapping receive lifetimes on both routers before changing
the sending key. Secrets are marked for `strip-private` redaction.

OSPFv2 also supports interface plaintext authentication, multiple MD5 keys, and
an explicit `authentication none` override for area authentication. OSPFv3 can
use one manual `authentication key <id> algorithm <algorithm> secret <secret>`.
Authentication modes are mutually exclusive on a given interface.

## Timers and interface controls

Both families expose reference bandwidth, ECMP path count, administrative
distances, SPF throttling, minimum LSA arrival, aggregation, graceful restart,
helper controls, hello/dead/retransmit/transmit timers, cost, priority, and MTU
checking. Set all three SPF values together:

```text
set protocols ospf timers spf delay 20 initial-hold 100 maximum-hold 1000

set protocols ospfv3 timers spf delay 20 initial-hold 100 maximum-hold 1000
```

OSPFv2 adds NBMA neighbors, fast hello, retransmit windows, flood reduction,
prefix suppression, neighbor filters, DSCP, per-address interface overrides,
and startup/shutdown maximum-cost advertisements. `timers refresh` controls
FRR's `refresh timer`. Removing a process with `max-metric on-shutdown` waits
for that configured announcement interval before the commit finishes.

Proactive ARP and per-interface sockets retain FRR's enabled defaults. Use
`disable-proactive-arp` or `disable-socket-per-interface` to disable them.
`socket buffer send|receive|all` sets requested socket buffer sizes in bytes;
`all` cannot be combined with direction-specific sizes.

OSPFv3 adds on-wire interface `instance-id`, an OSPF packet `mtu`, static
link-local neighbors, and `neighbor-options` for point-to-point/multipoint
links. The interface instance ID does not start an additional OSPF process.

## VRFs and operational commands

The same settings apply under a named VRF. A participating interface must belong
to that VRF.

```text
set vrf name BLUE table 100
set interfaces ethernet eth1 vrf BLUE

set vrf name BLUE protocols ospf options router-id 192.0.2.1
set vrf name BLUE protocols ospf interface eth1 area 0
```

```text
show ip ospf
show ip ospf neighbor detail
show ip ospf interface eth1
show ip ospf database router
show ip ospf route
show ip route ospf

show ipv6 ospf neighbor
show ipv6 ospf interface traffic
show ipv6 ospf database router detail
show ipv6 ospf vrf BLUE route
show ipv6 route ospf6
show ipv6 route vrf BLUE ospf6

clear ip ospf neighbor 192.0.2.2
clear ipv6 ospf vrf BLUE process
```

Reset commands interrupt the selected adjacency or process. Use show commands
first. Native JSON is available through `| raw` for displays that FRR supports.

## Current boundaries

Numbered OSPFv2 processes, virtual links, per-address plaintext authentication,
and FRR's hidden `lsa-refresh`/`maxage-delay` options are deferred. Ordinary
interface plaintext authentication remains available. OSPFv2 opaque capability
and Router Information settings are available in the default VRF only. BFD,
DMVPN, MPLS traffic engineering, segment routing and fast reroute are separate
roadmap work.

See the [complete command tree](command-tree.md) for every leaf and range, and
the [implementation guide](../dev/ospf.md) for lifecycle and native limitations.
