# IS-IS

IS-IS carries IPv4 and IPv6 reachability through `protocols isis`. Use the same
commands below `vrf name <name> protocols isis` for a named VRF. Each routing
instance has one IS-IS configuration; there is no separate process-number node.

## Enable routing

```text
set protocols isis net 49.0001.0000.0000.0001.00
set protocols isis options level level-2
set protocols isis interface eth1 address-family ipv4-unicast address-family ipv6-unicast network point-to-point
set protocols isis interface lo address-family ipv4-unicast address-family ipv6-unicast passive
```

The NET contains an area address, six-byte system ID and zero selector. Give each
router a distinct system ID. Up to three NETs on one instance may be configured; they must share that system
ID. Level-1 neighbors also need a common area address.

An interface must select at least one address family. `passive` advertises its
prefixes without forming adjacencies; `passive disable` explicitly makes it active.
Ordinary interfaces are active by default. Participating interfaces must belong to
the configured VRF. IPv6 must be enabled on interfaces carrying IPv6 reachability.

The native defaults are level-1-2, wide metrics, dynamic hostname advertisement,
broadcast circuits and metric 10. Use point-to-point only on links with the
appropriate topology. IS-IS runs directly over the link layer; the interface's IP
address is not its adjacency transport address.

## Levels, metrics and timers

```text
set protocols isis options metric-style wide lsp-mtu 1400 log-adjacency-changes
set protocols isis interface eth1 circuit-type level-2
set protocols isis interface eth1 level level-2 metric 20 priority 32
set protocols isis interface eth1 level level-2 timers hello-interval 3 hello-multiplier 10 csnp-interval 10 psnp-interval 2
set protocols isis level level-2 timers lsp-generation 5 lsp-refresh 600 lsp-lifetime 1200 spf-interval 1
set protocols isis spf delay initial 50 short 100 long 500 hold-down 1000 time-to-learn 500
```

Interface and LSP timer values are seconds; the five IETF SPF backoff values are
milliseconds and must be supplied together. LSP refresh must exceed generation
interval and be at least 300 seconds below maximum lifetime. Narrow metrics
cannot exceed 63. Additional topologies require wide metrics.

`options overload administrative` prevents ordinary transit use until removed.
`options overload on-startup <seconds>` provides a startup grace period.
`advertise-high-metrics` discourages transit with high link metrics;
`advertise-passive-only` limits advertised connected prefixes to passive circuits.
These controls have different purposes and do not shut down the process.

## Authentication and hello behavior

```text
set protocols isis level level-2 authentication mode md5 password "example-key" snp validate
set protocols isis interface eth1 authentication mode md5 password "example-key"
set protocols isis interface eth1 hello-padding during-adjacency-formation
```

Level authentication protects LSPs and optionally sequence-number PDUs. Interface
authentication protects hellos. Both require a mode and password; configure matching
values on peers. `plaintext` is also available. `snp send-only` authenticates sent
SNPs, while `validate` also validates received SNPs.

Hello padding supports `always`, `during-adjacency-formation` and `disabled`.
Removing the setting restores the native `always` default. Three-way handshakes
remain enabled unless `disable-three-way-handshake` is configured.

## IPv6 multi-topology and local protection

```text
set protocols isis topology ipv6-unicast
set protocols isis interface eth1 topology ipv6-unicast
set protocols isis interface eth1 level level-2 fast-reroute lfa
set protocols isis level level-2 fast-reroute priority-limit high
set protocols isis level level-2 fast-reroute tiebreaker 1 type downstream
```

IPv6 can use a separate topology instead of sharing IPv4's topology. Enable the
additional topology on the process. Interfaces participate by default; their
explicit topology entries can document that choice or disable participation. Both peers must
agree on their topology configuration. Process `topology <name> overload` sets
that topology's overload bit; interface `topology <name> disable` disables its use
on that circuit.

Local LFA protection computes alternate next hops when the topology permits it.
Interface `exclude-interface` removes a link from backup selection. Process options
control priority, load sharing and ordered tiebreakers. BFD, remote LFA, TI-LFA,
Segment Routing, MPLS and Flex-Algo are outside this implementation.

## Redistribution and default routes

```text
set policy prefix-list ipv4 ISIS-EXPORT rule 10 action permit prefix 192.0.2.0/24
set policy route-map ISIS-EXPORT rule 10 action permit match ipv4 prefix-list ISIS-EXPORT
set protocols isis address-family ipv4-unicast level level-2 redistribute static metric 20 route-map ISIS-EXPORT
set protocols isis address-family ipv6-unicast level level-2 redistribute connected metric 20
set protocols isis address-family ipv4-unicast level level-2 default-originate
```

Redistribution and default origination select both an address family and routing
level. That level must be enabled on the process. `metric` and `route-map` are
optional; a referenced route-map must exist. `default-originate always` advertises
a default without requiring an installed default route.

Other protocols can redistribute IS-IS routes:

```text
set protocols bgp address-family ipv4-unicast redistribute isis route-map ISIS-EXPORT
set protocols ospf redistribute isis metric 20
set protocols ospfv3 redistribute isis metric 20
set protocols rip redistribute isis metric 2
set protocols ripng redistribute isis metric 2
```

Apply deliberate export policies when redistributing between protocols to avoid
feeding routes back into their originating protocol.

## Inspect and reset

```text
show isis
show isis neighbor
show isis interface detail
show isis database detail
show isis route level level-2
show isis fast-reroute summary
show isis vrf BLUE summary
show isis vrf all neighbor
show ip route isis
show ipv6 route isis
show log isis
clear isis neighbor
clear isis vrf BLUE neighbor
```

A bare `show isis` shows the default instance summary. Displays can select a VRF
or `vrf all`; supported displays also offer `json`. An unscoped adjacency clear
acts only on the default VRF. `clear isis vrf all neighbor` explicitly clears all
instances. Clearing adjacencies does not remove their configuration.

See the [command tree](command-tree.md) for the complete syntax and the
[developer guide](../dev/isis.md) for implementation and test details.
