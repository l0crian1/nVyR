# BGP unicast

For implementation and testing, see the [developer guide](../dev/bgp.md).

For native route displays, neighbor status and peer resets, see
[BGP operational commands](bgp-operations.md).

BGP applies across configured routing instances. Failed changes attempt to restore
the previous configuration. Use `save` to retain committed changes across reboot.

## External IPv4 example

```text
set policy prefix-list ipv4 EXPORT rule 10 action permit prefix 203.0.113.0/24
set policy prefix-list ipv4 IMPORT rule 10 action permit prefix 0.0.0.0/0

set protocols bgp local-as 65000
set protocols bgp parameters router-id 192.0.2.1

set protocols bgp neighbor 192.0.2.2 remote-as 65001
set protocols bgp neighbor 192.0.2.2 update-source 192.0.2.1
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast prefix-list in IMPORT out EXPORT

set protocols bgp address-family ipv4-unicast network 203.0.113.0/24

commit
```

The local transport address must be usable in the appropriate routing domain.
Network import checking and mandatory eBGP policies default to disabled. Enable
`parameters network import-check enable` to require an exact route for network
advertisements, and `parameters ebgp-requires-policy enable` to require explicit
inbound and outbound policies for every active external family, including
dynamic neighbors. An access-list becomes FRR's `distribute-list`; it
cannot coexist with a prefix-list in the same direction. Policies must exist,
and referenced policies cannot be deleted.

## IPv6, VRFs, and peer groups

The same tree is available at `vrf name <name> protocols bgp`:

```text
set vrf name BLUE table 101

set vrf name BLUE protocols bgp local-as 65000 parameters router-id 192.0.2.10

set vrf name BLUE protocols bgp peer-group INTERNAL remote-as 65000 update-source lo
set vrf name BLUE protocols bgp peer-group INTERNAL address-family ipv6-unicast next-hop-self

set vrf name BLUE protocols bgp neighbor 2001:db8::2 peer-group INTERNAL

set vrf name BLUE protocols bgp address-family ipv6-unicast network 2001:db8:10::/48
```

Peer groups are scoped to their BGP instance. Neighbors inherit their group's
settings and enabled families; direct settings override inherited values where
FRR supports doing so. A fixed group remote AS cannot be overridden with a
different AS. A member may narrow its group's community selection. FRR 10.7.1
ignores attempts to re-enable a class disabled by the group, so enable those
classes on the group first.

`update-source` accepts an interface or unicast IPv4/IPv6 address. An explicit
address must match the transport neighbor's family; the activated NLRI family
is independent. Interface references protect configured interface deletion.
IPv6 link-local peers require `interface <name>`. An interface name used as the
neighbor key creates an unnumbered peer; `ipv6-only` restricts its transport to
IPv6. Neither requires adding another routing domain.

By default, no family is activated implicitly. Creating an `ipv4-unicast` or
`ipv6-unicast` node beneath a neighbor or its group activates that family.
`parameters default ipv4-unicast enable` and `ipv6-unicast enable` opt into
implicit activation. nVyR reconciles existing peers as well as newly created
ones when these settings change.
The same declarative behavior applies to `parameters default shutdown`: it
shuts down configured peers by default, and clearing it restores peers without
an explicit `shutdown` setting.

## Settings

- Instance: `local-as`, `description`, and the anchored `parameters` tree.
- General parameters: `router-id`, `cluster-id`, `timers keepalive|holdtime`,
  `shutdown`, `log-neighbor-changes`, best-path controls, confederations,
  graceful restart, dynamic listeners, MED controls and other behavior below.
- Neighbor and peer group: `remote-as`, `description`, `password`, `shutdown`,
  `update-source`, `ebgp-multihop`, `ttl-security hops`, `passive`, and
  `timers keepalive|holdtime|connect`.
- Neighbor/group family: `route-map import|export`, `prefix-list in|out`,
  `access-list in|out`, `next-hop-self`, `route-reflector-client`,
  `default-originate [route-map <name>]`, `maximum-prefix limit <count>`, and repeatable
  `send-community standard|extended|large`.
- Instance family: `network <prefix> [route-map <name>]`,
  `redistribute connected|static|kernel [metric <value>] [route-map <name>]`,
  `aggregate-address <prefix> [as-set] [summary-only]`, and
  `maximum-paths ebgp|ibgp` (1–256 for the pinned FRR build).

Instance descriptions remain nVyR metadata. Neighbor descriptions are sent to
FRR. `parameters shutdown enable` shuts down all peers while preserving their configuration;
individual `shutdown` remains in force when the global shutdown is removed.

Absent timer overrides use FRR's 60-second keepalive and 180-second hold time.
Hold time must be zero or at least three seconds; keepalive must be positive and
no more than one third of a nonzero hold time. Use both values zero to disable
the hold/keepalive timers. Neighbor timer overrides inherit missing values from
their group and then the instance. Multihop and TTL security are mutually
exclusive. Route-reflector clients must be internal neighbors.

FRR sends standard, extended, and large communities by default. Configuring
`send-community` selects exactly the listed classes. Removing the setting
restores native defaults or peer-group inheritance.

The generated [command tree](command-tree.md) contains every full path.
Additional AFI/SAFIs remain deferred. See [BGP operational commands](bgp-operations.md)
for route and neighbor inspection, refreshes and session resets.

## Peer identities and transport

`remote-as` accepts a number, `internal` (the local AS), `external` (a different
AS), or `auto` (discover the peer's AS). An alternate local AS is separate from
the instance's `local-as`:

```text
set protocols bgp neighbor 192.0.2.2 remote-as 65002

set protocols bgp neighbor 192.0.2.2 local-as number 65100
set protocols bgp neighbor 192.0.2.2 local-as no-prepend replace-as dual-as
```

The modifier path is nested: `replace-as` requires `no-prepend`, and `dual-as`
requires both. `no-prepend` avoids adding the alternate AS to received paths;
`replace-as` advertises the alternate identity instead of the real local AS;
`dual-as` accepts either identity during migration. Alternate local AS is for
external peers and must differ from the instance AS.

Interface-based and addressed link-local peers use distinct syntax:

```text
set protocols bgp neighbor eth1 remote-as external ipv6-only
set protocols bgp neighbor eth1 address-family ipv4-unicast
set protocols bgp neighbor eth1 address-family ipv6-unicast
```

```text
set protocols bgp neighbor fe80::2 interface eth2 remote-as 65002
set protocols bgp neighbor fe80::2 address-family ipv6-unicast
```

`interface` selects the link to an addressed neighbor; `update-source` selects
the local transport source. Interface references protect configured interface
deletion. Unnumbered peers use IPv6 link-local discovery and can carry both
unicast families.

Peer/group controls also include:

- `shutdown`, `passive`, `graceful-shutdown`: valueless switches. Delete a switch
  to restore inherited or native behavior.
- `graceful-restart helper|restart|disable`: one mutually exclusive restart mode.
- `disable-enforce-first-as`, `disable-connected-route-check`: explicit exemptions.
- `port <1-65535>`, `tcp-mss <1-65535>`: transport parameters.
- `timers advertisement-interval <0-600>` and `timers delay-open <1-240>`: seconds.

Peer-group negative overrides are deferred: the pinned FRR does not reliably
override or persist them. Change the group or configure the peer independently.
`address-family <family> disable` is supported for family deactivation.

## Capabilities and roles

The anchored `capability` node has valueless `extended-nexthop`, `dynamic`,
`link-local`, `software-version`, `disable-fqdn`, `disable-negotiation`,
`strict-match`, and `override` children. Software version uses the legacy
encoding. `strict-match` and `override` conflict; disabling negotiation cannot
be combined with other explicit capabilities.

```text
set protocols bgp neighbor 192.0.2.2 capability dynamic software-version
set protocols bgp neighbor 192.0.2.2 role type provider strict
```

Roles describe the local relationship: `provider`, `customer`, `peer`,
`rs-server`, or `rs-client`. `strict` rejects peers without a compatible role.
`route-server-client` is a separate address-family behavior and preserves the
next hop. Roles and route-server behavior apply to external peers.

## Unicast family controls

These settings work beneath either a neighbor or peer group and beneath either
`address-family ipv4-unicast` or `address-family ipv6-unicast`.

```text
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast next-hop-self force

set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast maximum-prefix limit 100000 threshold 90 warning-only force
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast maximum-prefix-out 10000
```

`next-hop-self force` also rewrites next hops learned through iBGP. Received
prefix limits can warn or close the session; `restart <minutes>` retries after
closure and conflicts with `warning-only`. `force` counts rejected routes too
and requires inbound soft reconfiguration. Storing those routes consumes memory.

AS-path controls are `allowas-in count <1-10>` or `allowas-in origin`, with an
optional `route-map`; `as-override`; and `remove-private-as`, optionally followed
by `all`, `replace`, or `all replace`. Count and origin are mutually exclusive.
`all` removes private AS numbers from mixed paths; `replace` substitutes the
local AS. These controls apply to external peers.

```text
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast allowas-in count 2
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast remove-private-as all replace

set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast as-path-list import IMPORT_AS export EXPORT_AS
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast weight 100
```

The named AS-path lists must already be configured. `weight` is local to this
router. `attribute-unchanged as-path next-hop med` selects attributes to preserve
on export; individual fields may be configured separately.

Conditional advertisement references existing route maps:

```text
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast conditional-advertisement advertise-map ADVERTISE exist-map TRIGGER
```

Use exactly one of `exist-map` and `non-exist-map`. The instance's
`parameters conditional-advertisement timer` controls reevaluation.

```text
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast addpath transmit best-selected 2
set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast addpath receive-limit 4
```

AddPath transmit choices are `all` or `best-selected <1-6>`. Reception can instead
be disabled with `disable-receive`, which conflicts with a receive limit.
`best-per-as` is deferred because it enables an affected FRR MED setting; see
[upstream issues](../dev/upstream-issues.md#frr-bgp-003-general-parameter-flag-collisions-and-incorrect-writer-flags).

## Aggregation, redistribution and route preference

Both instance unicast families support aggregate `route-map`, `origin
igp|egp|incomplete`, `matching-med-only`, and `suppress-map`, in addition to
`as-set` and `summary-only`. A suppress-map selects components to suppress and
cannot coexist with summary-only. A peer's `unsuppress-map` can advertise selected
suppressed components to that peer.

```text
set protocols bgp address-family ipv4-unicast aggregate-address 10.0.0.0/8 origin igp matching-med-only suppress-map SUPPRESS

set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast unsuppress-map EXCEPTIONS
```

Redistribution accepts `connected`, `static`, and `kernel`, each with optional
`metric` and `route-map`. Distances default to external 20, internal 200, local 200;
omitted components retain those defaults.

```text
set protocols bgp address-family ipv4-unicast redistribute kernel metric 50 route-map KERNEL_ROUTES
set protocols bgp address-family ipv4-unicast distance external 30 internal 210 local 220

set protocols bgp address-family ipv6-unicast next-hop prefer-global
```

All examples are also available under `vrf name <name> protocols bgp`.
BFD, RPKI, extended-community policies and VRF route leaking remain separate work.

## General parameters and negation

Boolean parameters take `enable` or `disable`; deleting the setting restores
the nVyR default. These defaults also apply when no `parameters` node is
configured. Configuring static routing alone does not enable BGP.

These four parameters default to `disable`:

```text
set protocols bgp parameters ebgp-requires-policy enable
set protocols bgp parameters reject-as-sets enable
set protocols bgp parameters default ipv4-unicast enable
set protocols bgp parameters network import-check enable
```

The following switches default to `enable`: `client-to-client reflection`,
`ebgp-connected-route-check`, `enforce-first-as`, `fast-external-failover`,
`hard-administrative-reset`, `ipv6-auto-ra`, `suppress-duplicates`,
`graceful-restart notification`, and `graceful-restart end-of-rib`.
Other Boolean switches default to `disable`. The positive
`ebgp-connected-route-check` and `end-of-rib` names translate to FRR's negative
commands when disabled.

Examples of the nested controls:

```text
set protocols bgp parameters fast-external-failover disable

set protocols bgp parameters bestpath as-path multipath-relax enable
set protocols bgp parameters bestpath med confed enable missing-as-worst enable
set protocols bgp parameters bestpath bandwidth skip-missing

set protocols bgp parameters cluster-id 192.0.2.10
set protocols bgp parameters route-reflector allow-outbound-policy enable

set protocols bgp parameters confederation identifier 64512 peers 65001 peers 65002

set protocols bgp parameters graceful-restart mode restart restart-time 120 stalepath-time 360
set protocols bgp parameters long-lived-graceful-restart stale-time 300

set protocols bgp parameters default local-preference 200
set protocols bgp parameters default software-version-capability legacy

set protocols bgp parameters max-med administrative 4294967294
set protocols bgp parameters max-med on-startup time 60 med 1000

set protocols bgp parameters minimum-holdtime 30
set protocols bgp parameters conditional-advertisement timer 60

set protocols bgp parameters suppress-fib-pending enable suppress-fib-pending-delay 1000
set protocols bgp parameters tcp-keepalive idle 60 interval 10 probes 3

set protocols bgp parameters dampening state enable half-life 15 reuse 750 suppress 2000 max-suppress-time 60
set protocols bgp parameters route-map delay-timer 5
```

Graceful restart uses `mode helper|restart|disable` (default `helper`). Its
notification, forwarding-state and end-of-RIB switches are independent of the
mode. Long-lived stale time defaults to zero (disabled). Dampening is IPv4
unicast in the default VRF only, following FRR's documented limitation.
`route-map delay-timer` affects the whole bgpd process and is
therefore configured only under default-VRF `protocols bgp parameters`.

Dynamic neighbors use existing local peer groups:

```text
set protocols bgp peer-group CLIENTS remote-as 65001 address-family ipv4-unicast

set protocols bgp parameters listen limit 100
set protocols bgp parameters listen range 192.0.2.0/24 peer-group CLIENTS
```

Labeled-unicast remains deferred. Native FRR defects also defer
`always-compare-med`, `deterministic-med`, `bestpath use-imported-attributes`,
the latest software-version capability encoding, the default-originate scan
timer, and an instance shutdown message. See [upstream issues](../dev/upstream-issues.md)
for reproductions and conditions for revisiting them.
`minimum-holdtime` is supported except for 180 seconds, which the same release
incorrectly omits from its configuration writer. The CLI rejects that value
at entry, including when loading configuration.

## Neighbor validation

Configured hold times must be zero or 3–65535 seconds. Timer relationships,
including inherited peer-group values, are checked at commit. Authentication
passwords cannot have leading, trailing or repeated whitespace because FRR
would change the secret; single spaces between words are supported.

Neighbors cannot use an address assigned to this router in the same VRF.
Verification includes configured interface/VIF addresses and, during a normal
commit, live addresses such as DHCP leases. `commit check` checks proposed
interface addresses and reports that live checks are deferred until commit.
An address belonging to a different VRF remains a valid peer destination.
