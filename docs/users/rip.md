# RIP and RIPng

RIPv1/RIPv2 use `protocols rip`; IPv6 uses `protocols ripng`. The same commands
are available under `vrf name <name> protocols`. Interfaces, policies and timers
are anchored, so related settings can be entered on one line.

## Enable routing

```text
set protocols rip version 2
set protocols rip interface eth1
set protocols rip interface eth2 passive
set protocols ripng interface eth1
set protocols ripng interface eth2 passive
```

An `interface` entry enables the protocol on that link. Alternatively, `network`
selects interfaces whose local address is within a prefix:

```text
set protocols rip network 192.0.2.0/24
set protocols ripng network 2001:db8:10::/64
```

These commands select participating interfaces; they do not redistribute every
route covered by the prefix. `route <prefix>` explicitly originates a protocol
route, and `redistribute` imports routes from another source. RIPng also supports
`aggregate-address <prefix>`.

## Passive interfaces and split horizon

`passive` suppresses outgoing updates while allowing reception. `passive disable`
makes an interface active. RIP can set a process-wide passive default:

```text
set protocols rip passive-default
set protocols rip interface eth1 passive disable
```

RIPng has per-interface passive settings, but no process-wide passive-default.
Native FRR defaults apply when settings are absent: ordinary split horizon,
30-second updates, 180-second route timeout, 120-second garbage collection, and
redistribution metric 1. RIP's unset version sends RIPv2 and accepts RIPv1/RIPv2;
`version 2` explicitly selects RIPv2 for both directions.

```text
set protocols rip interface eth1 split-horizon poisoned-reverse
set protocols ripng interface eth1 split-horizon disable
set protocols rip timers update 10 timeout 60 garbage-collection 40
set protocols rip maximum-paths 4
```

Configure either `disable` or `poisoned-reverse`, not both. A bare
`split-horizon` selects ordinary split horizon. Individual timer settings use the
native defaults for the other two timers.

## Policies and redistribution

Use existing family-specific access-lists and prefix-lists, and shared route-maps:

```text
set policy prefix-list ipv4 RIP-LAN rule 10 action permit prefix 192.0.2.0/24
set policy route-map RIP-EXPORT rule 10 action permit match ipv4 prefix-list RIP-LAN
set policy route-map RIP-EXPORT rule 10 set metric 3 tag 100
set protocols rip redistribute connected route-map RIP-EXPORT
set protocols rip interface eth1 distribute-list in prefix-list RIP-LAN
```

`distribute-list in|out` is available globally and per interface. An access-list
and prefix-list may be used together. Interface `route-map in|out` applies a
policy to updates on that interface. An `offset-list in|out` requires both an
access-list and a metric; it adds that metric to matching routes.

`default-information originate` advertises a default route. `default-metric`
sets the redistribution metric, with per-source `metric` and `route-map` options.
RIP also supports process `distance` and source-specific distance overrides:

```text
set protocols rip source-distance 192.0.2.2/32 distance 125 access-list RIP-SOURCES
```

The source prefix selects the advertising router; the optional access-list
filters destinations to which that distance applies. RIPng has no corresponding
distance command in the shipped FRR implementation.

## RIPv2 authentication and compatibility

```text
set policy key-chain RIP-AUTH key 1 secret "example-key" algorithm md5
set protocols rip interface eth1 authentication mode md5 key-chain RIP-AUTH
```

Authentication requires `mode text|md5` and exactly one of `password` or
`key-chain`. Direct passwords are at most 16 characters; MD5 keychain IDs must
fit in 0–255. `md5-auth-length rfc|old-ripd` is available for peers needing a
specific MD5 compatibility format. Omitting it retains FRR's native default.

Interface `send-version` and `receive-version` accept `1`, `2`, `both`, or `none`.
`v2-broadcast` sends RIPv2 broadcasts instead of multicast. `neighbor <address>`
adds a unicast update destination. RIPng has none of these IPv4-only RIP controls.

## Inspect and reset

```text
show ip rip
show ip rip status
show ip rip vrf BLUE status
show ipv6 ripng
show ipv6 ripng vrf BLUE status
show ip route rip
show ipv6 route ripng
show log rip
show log ripng follow
clear rip
clear ripng vrf BLUE
clear rip all
```

Displays support `vrf all`. A bare `clear rip` or `clear ripng` clears learned
routes only in the default routing instance. Use `all` explicitly to clear every
instance. Neither form deletes configuration.

For the complete syntax, see the [command tree](command-tree.md). BFD is deferred.
Implementation and test details are in the [developer guide](../dev/rip.md).
