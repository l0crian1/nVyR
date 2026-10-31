# Firewall configuration

For implementation and testing, see the [developer guide](../dev/firewall.md).

For practical introductions and complete scenarios, see [firewall maps](firewall-maps.md)
and [match-groups](firewall-match-groups.md). Those guides explain multi-field
lookups, their benefit over long rule lists, and how to inspect matching traffic.

## Find a feature

- [Family-neutral inet rules](#family-neutral-inet-rules), [rules and negation](#configuration), [named chains](#named-chains-and-jumps),
  [zones](firewall-zones.md), and [VRF/link-group matching](#linux-link-groups-and-vrf-ingress-interfaces).
- [Maps](#named-maps), [match-groups](#match-groups), [single-field groups](#single-field-groups),
  [ICMP groups](#icmp-groups), [dynamic groups](#dynamic-address-and-match-groups),
  and [GeoIP groups](firewall-geoip.md).
- [Source validation](#source-validation), [FIB](#fib-lookups), [ICMP](#icmp-type-and-code-matches), [TCP flags/length](#tcp-flags-and-packet-length),
  [connection tracking](#connection-tracking-matches), [timeout groups](firewall-timeouts.md),
  and [transport ports](#transport-port-matching).
- [Limits](#rate-and-connection-limits), [shared limits/counters](#shared-limit-and-counter-groups),
  [quotas](#byte-quotas), [logging](#kernel-logging-options), and [reject responses](#reject-responses).
- [Flowtables](#flowtables), [global enrollment](#global-flowtable-enrollment),
  [global kernel settings](#global-kernel-settings), [fail-safe protection](firewall-failsafe.md),
  and [operational views](nftables-operational-data.md#cli-display).

## Packet tracing

Add the valueless `nftrace` option to a rule to trace packets that reach and match
it. This is available in IPv4, IPv6 and inet rules, including named chains, raw
hooks, ingress, and the fail-safe firewall. It sets `meta nftrace set 1` after
matches and before the verdict; it does not change the verdict.

```sql
set firewall ipv4 prerouting raw rule 10 description "Trace SSH from the test client"

set firewall ipv4 prerouting raw rule 10 protocol tcp destination-port 22
set firewall ipv4 prerouting raw rule 10 source-address 192.0.2.10
set firewall ipv4 prerouting raw rule 10 nftrace action continue
commit
```

Monitor from operational mode, or prefix these commands with `run` in configuration mode:

```text
monitor firewall trace
monitor firewall trace duration 30s

monitor firewall trace duration 2m save /config/traces/ssh.jsonl
```

`duration` accepts positive values in seconds (`s`), minutes (`m`), hours (`h`),
or days (`d`), up to 2147483647 seconds. Without it, monitoring continues until
Ctrl+C. Both options are anchored and may appear in either order. The monitor
requires net-admin access or higher and reports the number of captured events.

The terminal displays packet identifiers, native events and identifiable nVyR
rule paths. Generated rules and other tables retain their native descriptions.
Tracing begins at the enabling rule: earlier verdicts and flowtable bypasses can
prevent packets from reaching that rule. Use ingress or prerouting when the
earlier part of the packet's path matters.

Saved files contain one JSON object per event, including its timestamp, original
native text, and parsed fields when available. A capture header records native
chain hooks, and a completion record distinguishes a stopped capture from an
unfinished file. The native trace stream is text,
even with nft's JSON option. Files are created privately under `/config/traces/`;
the directory is created automatically, symlinks are not followed, and existing
files are never overwritten. Complete records are flushed as they arrive and
remain available after cancellation or a capture error.

Inspect a saved capture with `show firewall trace /config/traces/ssh.jsonl`.
Select `id <trace-id>` for its ordered story or add `detail` for the original
events. See [Packet trace analysis](firewall-tracing.md) for filters, examples,
conntrack observations, and interpretation of repeated trace IDs.

Stopping the monitor **does not disable configured tracing**. Remove `nftrace`
and commit when finished:

```sql
delete firewall ipv4 prerouting raw rule 10 nftrace
commit
```

## Family-neutral inet rules

Use `firewall inet` for a policy that applies equally to IPv4 and IPv6. Numbered
inet rules run directly in the hook's base chain, after global state policies and
global flow enrollment, but before IPv4/IPv6 dispatch. There is no extra jump.

```sql
set firewall inet forward filter rule 10 description "Trust the inside interface"
set firewall inet forward filter rule 10 counter

set firewall inet forward filter rule 10 inbound-interface eth1 action accept
```

A matching `accept`, `drop`, or `reject` decides the verdict at that hook. A miss
or `continue` proceeds to later rules and then family dispatch. `return` in a
base chain ends that chain with its accept policy; use `continue` to reach the
family policies. Inet hooked chains have **no configurable default action**.
Named inet chains retain their own defaults and normal jump/return semantics.

Available paths are `input filter`, `forward filter`, `output filter`,
`prerouting raw`, `output raw`, `ingress filter`, and `name <chain>`.
Ingress requires `interface <name|prefix*>`; its direct rules are restricted to
those attachments even when IPv4/IPv6 bind other devices to the same hook.
Fail-safe inet rules are also available, excluding ingress and flow enrollment.

Neutral fields include interfaces and their groups, link groups, MAC addresses
and groups, protocols, transport ports and groups, TCP flags/MSS, packet length,
packet type, marks, neutral connection metadata/accounting, and FIB queries.
Logging, counters, quotas, rate/connection limits, and compatible actions retain
their existing syntax. Hook restrictions apply through groups and nested jumps.

IP addresses and their groups, connection addresses/family, ICMP type/code/groups,
TTL/hop-limit, and DSCP are unavailable under inet. Use IPv4/IPv6 rules for
those matches. FIB lookup selectors still choose source or destination from the
packet being evaluated; they do not configure an IP address.

### Inet groups and ICMPX

Maps, match-groups, and limit-groups have an `inet` scope with only neutral keys.
Inet maps return verdicts. Shared interface, MAC, port, counter, quota, and log
groups work without another family-specific copy. Dynamic inet match-groups can
be updated with `add-to-group match-group <name>` and cleared with the existing
runtime commands. The five-field/64-byte key limits still apply.

```sql
set firewall group map inet SERVICES description "Common services for both IP families"
set firewall group map inet SERVICES counter

set firewall group map inet SERVICES match protocol destination-port
set firewall group map inet SERVICES result-type verdict

set firewall group map inet SERVICES entry HTTPS protocol tcp destination-port 443 result action accept
set firewall group map inet SERVICES entry DNS protocol udp destination-port 53 result action accept

set firewall inet input filter rule 20 map SERVICES
```

```sql
set firewall group match-group inet LOCAL_SERVICE description "Inside DNS clients"

set firewall group match-group inet LOCAL_SERVICE match inbound-interface protocol destination-port

set firewall group match-group inet LOCAL_SERVICE entry DNS inbound-interface eth1 protocol udp destination-port 53

set firewall inet forward filter rule 30 match-group LOCAL_SERVICE action accept
```

Inet `reject-response` accepts `no-route`, `host-unreachable`, `port-unreachable`,
and `admin-prohibited`. These emit native ICMPX responses, selecting the proper
ICMP or ICMPv6 response for the packet. The global reject response is inherited
when no rule override is set. `tcp-reset` requires a positive TCP-only match.
ICMPX is a reject abstraction, not a new ICMP matching protocol.

```sql
set firewall inet input filter rule 100 description "Reject other traffic on the guest interface"

set firewall inet input filter rule 100 inbound-interface eth2 action reject
set firewall inet input filter rule 100 reject-response admin-prohibited
```

```text
show firewall inet
show firewall inet forward filter rule 10
show firewall inet input filter detail
show firewall inet input filter limits
show firewall inet input filter rule 10 quota
show firewall group map inet SERVICES
show firewall group match-group inet LOCAL_SERVICE
show log firewall inet forward filter rule 10
```

## Ingress filtering

`firewall ipv4 ingress filter` and `firewall ipv6 ingress filter` inspect packets
on selected interfaces before routing, connection tracking, and flowtable lookup.
They use the native `inet ingress` hook at priority `-10`; flowtables use priority
`0`. An ingress accept permits the packet to continue to later hooks, where the
normal firewall policy still applies.

Each family requires at least one `interface`. Repeat it for multiple interfaces,
or use a trailing prefix wildcard. Interfaces do not need to exist at commit or
boot: the kernel attaches the hook when a matching device appears. IPv4 and IPv6
can select different interfaces. Ingress is not available under `firewall fail-safe`.

```sql
set firewall ipv4 ingress filter interface eth1
set firewall ipv4 ingress filter interface 'veth*'
set firewall ipv4 ingress filter default-action accept

set firewall ipv4 ingress filter rule 10 description "Discard unexpected SSH sources early"
set firewall ipv4 ingress filter rule 10 counter

set firewall ipv4 ingress filter rule 10 protocol tcp destination-port 22
set firewall ipv4 ingress filter rule 10 source-address not 192.0.2.0/24
set firewall ipv4 ingress filter rule 10 action drop
```

The normal packet matches, logging, counters, quotas, packet/byte limits, dynamic
group updates, and `notrack` are available. Global connection-state policies do
not run at ingress. Connection matches and limits, FIB, outgoing-interface/link-group
matches, and flow-add actions are unavailable in ingress rules. Its `limit per`
choices also omit outgoing devices and connection marks.

Maps and match-groups retain their existing paths and can be reused across hooks
when their fields are compatible. Verification checks inherited fields, excluded
groups, dynamic update keys, shared limit keys, and every nested named-chain or
verdict-map jump against the calling hook. For example, a source-address map is
usable in ingress and forward; a connection-mark map is rejected at ingress.

Ingress runs before reassembly. Transport-port, TCP, and ICMP header matches
cannot inspect those headers in noninitial fragments. Inner tunnel matching is
deferred while intermittent native matching failures are investigated. This IP
ingress hook does not provide ARP or MPLS filtering.

### VLAN matches

`vlan id` matches the outer VLAN identifier (`0`–`4095`), and `vlan priority`
matches its priority code point (`0`–`7`). Configuring both requires both to match.
These fields are available in ingress rules, shared named chains, and group keys;
groups or named chains using them must be called only from ingress.

```sql
set firewall group match-group ipv4 EDGE description "Office VLAN traffic"
set firewall group match-group ipv4 EDGE counter

set firewall group match-group ipv4 EDGE match vlan id priority
set firewall group match-group ipv4 EDGE match source-address

set firewall group match-group ipv4 EDGE entry OFFICE vlan id 100 priority 5
set firewall group match-group ipv4 EDGE entry OFFICE source-address 192.0.2.0/24

set firewall ipv4 ingress filter interface eth1
set firewall ipv4 ingress filter rule 20 match-group EDGE action accept
```

Use the same fields in a map's `match` and `entry` nodes, adding its normal
`result-type` and entry `result`. Direct rules use `rule 20 vlan id 100 priority 5`.
The IPv6 syntax is identical apart from the family and address values.

### Ingress operational commands

```sql
show firewall ipv4 ingress filter
show firewall ipv4 ingress filter detail
show firewall ipv4 ingress filter rule 10

show firewall ipv4 ingress filter limits
show firewall ipv4 ingress filter rule 10 limit
show firewall ipv4 ingress filter quotas
show firewall ipv4 ingress filter rule 10 quota

show log firewall ipv4 ingress filter rule 10
```

Equivalent IPv6 commands are available. The unscoped `show firewall` includes
installed ingress chains. Logs use the `ING-filter` hook label, for example
`[ipv4-ING-filter-10-D]`.

## Global kernel settings

`firewall global-options` also controls kernel network behavior outside nftables.
Deleting a setting, its parent, or the entire firewall restores the nVyR default.
Configuring any part of `firewall` activates these defaults, even when their `global-options` parent nodes are absent. They appear in
`show running-configuration all firewall | commands`; the normal view shows only
explicit configuration.

Interface-capable global options apply to existing links and establish defaults
for new links, including dotted VIF names. Explicit [interface IP options](interfaces.md#ipv4-and-ipv6-options)
take precedence; deleting an override restores the global value.
These settings apply across VRFs in the router's network
namespace; they are not separate per-VRF settings.

### Ping and routing behavior

```sql
set firewall global-options ipv4 echo-request enable
set firewall global-options ipv4 broadcast-ping disable

set firewall global-options ipv6 echo-request enable
set firewall global-options ipv6 multicast-ping disable
set firewall global-options ipv6 anycast-ping enable

set firewall global-options ipv4 receive-redirects disable
set firewall global-options ipv4 send-redirects disable
set firewall global-options ipv4 source-route disable
set firewall global-options ipv4 directed-broadcast disable
set firewall global-options ipv4 log-martians disable

set firewall global-options ipv6 receive-redirects disable
set firewall global-options ipv6 source-route routing-header-2
```

These examples show defaults. Boolean choices accept `enable` or `disable`.
IPv6 `source-route` accepts `disable` or `routing-header-2`; it does not enable
arbitrary routing headers. Ping controls govern the router's responses, do not
bypass firewall rules, and do not control forwarded pings. IPv4 broadcast-ping
also covers multicast echo and timestamp requests. Kernel reverse-path filtering
remains disabled; use firewall FIB matching for source validation.

### ARP defaults

```sql
set firewall global-options ipv4 arp cache-timeout 30s
set firewall global-options ipv4 arp filter disable
set firewall global-options ipv4 arp announce any
set firewall global-options ipv4 arp ignore 0

set firewall global-options ipv4 arp accept disable
set firewall global-options ipv4 arp notify disable
set firewall global-options ipv4 arp proxy disable
set firewall global-options ipv4 arp proxy-pvlan disable
```

These are also defaults. Cache timeout is the base reachable time, not a fixed
entry-expiration deadline. `announce` accepts `any`, `subnet`, or `best-local`.
`ignore` accepts the kernel modes 0, 1, 2, 3, and 8; CLI descriptions explain each.
`accept` controls creation of new entries from gratuitous ARP and accepts
`disable`, `enable`, or `same-subnet`. `notify` generates gratuitous ARP on device
activation or MAC changes. Proxy PVLAN allows proxy replies back through the
receiving interface. The remaining ARP switches accept `enable|disable`.

### ICMP rate controls and SYN cookies

```sql
set firewall global-options ipv4 icmp-rate-limit interval 1s
set firewall global-options ipv4 icmp-rate-limit rate 1000
set firewall global-options ipv4 icmp-rate-limit burst 50

set firewall global-options ipv6 icmp-rate-limit interval 100ms

set firewall global-options syn-cookies enable
```

These defaults govern kernel-generated responses, independently of rule-level
limits. Intervals accept `ms`, `s`, `m`, `h`, or `d`; `0ms` disables spacing. Linux
rounds intervals up to its timer resolution. The IPv4 rate is messages per second.
The kernel's default ICMP type selections remain
unchanged. SYN cookies protect local TCP listening backlogs, not forwarded servers.

### Connection tracking

```sql
set firewall global-options connection-tracking hash-size auto
set firewall global-options connection-tracking maximum-entries auto
set firewall global-options connection-tracking maximum-expectations auto

set firewall global-options connection-tracking checksum-validation enable
set firewall global-options connection-tracking events auto
set firewall global-options connection-tracking log-invalid none

set firewall global-options connection-tracking tcp loose enable
set firewall global-options connection-tracking tcp maximum-retransmissions 3
```

`auto` capacities restore the native values recorded before configuration at boot.
Explicit positive integers override them. The kernel may round hash bucket counts
to its allocation granularity. Events accept `auto|enable|disable`; checksum
validation and TCP loose mode accept `enable|disable`.

The valueless `connection-tracking timestamp`, `connection-tracking tcp liberal`,
and `connection-tracking tcp ignore-invalid-rst` settings are disabled when absent.
Loose mode permits picking up connections without observing their handshake.
Liberal mode relaxes TCP window checks. Logging accepts one of `none`, `all`,
`icmp`, `icmpv6`, `tcp`, `udp`, or `udplite`. Conntrack diagnostics use the kernel
logger. Existing `connection-accounting` remains a separate valueless option.

### Tracking and flowtable timeouts

Timeouts accept whole `s`, `m`, `h`, or `d` durations, bounded to 2,147,483 seconds.
They control tracked state, not local application socket timeouts.

```sql
set firewall global-options connection-tracking timeout tcp established 5d
set firewall global-options connection-tracking timeout tcp syn-sent 2m
set firewall global-options connection-tracking timeout tcp syn-received 1m

set firewall global-options connection-tracking timeout udp unreplied 30s
set firewall global-options connection-tracking timeout udp stream 2m

set firewall global-options flowtable-timeout tcp 30s
set firewall global-options flowtable-timeout udp 30s
```

Additional defaults beneath `connection-tracking timeout`:

- TCP: `fin-wait 2m`, `close-wait 1m`, `last-ack 30s`, `time-wait 2m`, `close 10s`,
  `unacknowledged 5m`, and `max-retransmissions 5m`.
- ICMP and ICMPv6: `30s` each. Generic protocols: `10m`.
- GRE: `unreplied 30s` and `stream 3m`.
- SCTP: `closed 10s`, `cookie-wait 3s`, `cookie-echoed 3s`, `established 210s`,
  `shutdown-sent 3s`, `shutdown-received 3s`, `shutdown-ack-sent 3s`, and
  `heartbeat-sent 30s`.

The two flowtable timeouts apply across native flowtables, even before any table
exists. Expired offloaded connections return to normal connection tracking.

Kernel changes and nftables use compensating rollback: a failed apply restores
previous tunable values and the future-interface profile. They are not a single
atomic kernel transaction. These options are deliberately excluded from the
fail-safe subtree so it cannot define competing global settings.

## Configuration

IPv4 and IPv6 each support input, forward and output filters:

```text
set firewall global-options state-policy established action accept
set firewall global-options state-policy related action accept
set firewall global-options state-policy invalid action drop

set firewall ipv4 forward filter default-action drop
set firewall ipv4 forward filter default-log
set firewall ipv4 forward filter rule 10 action accept protocol tcp destination-port 22 counter last-used description "Allow SSH"
set firewall ipv4 forward filter rule 10 destination-port 8000-8100

set firewall ipv6 forward filter rule 20 action accept protocol ipv6-icmp

commit
```

Both IPv4 and IPv6 support `prerouting raw` and `output raw`. Their base chains
run at priority `raw` (-300), before connection tracking, using the same table
and family dispatch. Raw rules reuse the filter matches and add valueless
`notrack`. Prerouting raw omits `outbound-interface` and its group reference;
output raw omits `inbound-interface` and its group reference. Maps, match-groups,
and packet-path learning targets must respect the same interface restrictions:

```text
set firewall ipv4 prerouting raw rule 10 action continue protocol udp destination-port 5353 inbound-interface eth0 notrack counter log
set firewall ipv4 prerouting raw rule 20 action drop source-address 192.0.2.0/24

set firewall ipv6 prerouting raw rule 10 action continue protocol udp destination-port 5353 notrack

set firewall ipv4 output raw rule 10 action continue protocol udp destination-port 5353 outbound-interface eth0 notrack log

set firewall ipv6 output raw rule 10 action continue protocol udp destination-port 5353 outbound-interface eth0 notrack log
```

`notrack` excludes matching packets from connection tracking; `continue` evaluates
the next raw rule. An `accept` verdict ends this raw chain's evaluation but does not
bypass later filtering hooks. Raw rules still require an action and a port-bearing
protocol when matching ports. Like filters, an explicitly configured raw path has a direct default
action of `accept` and supports `default-action` and `default-log`. Global state
policies apply only at filter priority, after connection tracking. See the nftables
[connection tracking documentation](https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_connection_tracking_metainformation).

Any rule can have a valueless `disable` leaf. Disabled rules remain in candidate,
running and saved configuration but produce no nftables rule. Schema validation
still applies; rule-specific checks such as requiring an action resume when enabled.
Delete `disable` to enable a rule again.

### Negative matches

Use `not` immediately before an eligible match value. Positive and negative
values can coexist, with normal completion and validation on either side:

```text
set firewall ipv4 forward filter rule 10 action accept protocol tcp
set firewall ipv4 forward filter rule 10 source-address 10.0.0.0/8
set firewall ipv4 forward filter rule 10 source-address not 10.20.0.0/16
set firewall ipv4 forward filter rule 10 destination-port not 443
set firewall ipv4 forward filter rule 10 destination-port not 8443

delete firewall ipv4 forward filter rule 10 destination-port not 443
```

The last command removes only the `443` exclusion. `8443` and all other matches
remain configured. nftables evaluates the positive match and the negative match
together: `ip saddr { 10.0.0.0/8 } ip saddr != { 10.20.0.0/16 }`.
Multiple excluded values form one inequality against their set; a packet must
match none of them. There is no precedence or automatic subtraction in configd.

Supported firewall fields include IP/MAC addresses (including per-address masks),
interfaces, protocol, ports, marks, DSCP, state, connection status, packet-type,
ICMP type/code, TCP MSS, singleton-group references, and match-group references.
`ttl eq not 64` and `fib result route-type not local` are also supported. FIB
outbound-interface results allow negated names; use `exists`/`missing` directly
for existence tests. Lookup selectors, actions, maps, and rule statements are
not negatable. NAT syntax is unchanged.

Negating a match-group excludes complete tuples, not each component separately.
A positive group or map may coexist with negative matches on the same fields.
Within each polarity, the existing duplicate-field restrictions still apply.
Group references retain dependency protection and trigger consumer-chain rebuilds
when the referenced group changes.

Protocol and hook restrictions still apply. Excluding TCP does not satisfy the
positive port-protocol requirement for a port match. A masked field permits one
address per polarity. Connection-status combinations remain exact comparisons, including
`connection status not confirmed and snat`; they are not subset tests.

An inequality cannot match a missing header or TCP option: for example, a packet
without a TCP MSS option does not satisfy a negated MSS match. A negated group
lookup can increment its rule counter, but has no matching group element whose
counter or last-used statement can run. A FIB interface-name inequality also
matches the empty interface name returned when no route exists.

**Known nftables 1.1.7 limitation:** IPv6 DSCP interval sets have incorrect packet
matching behavior in the tested build, for both positive and negative comparisons.
Single values and sets of individual DSCP values were verified. nVyR does not
silently rewrite ranges to conceal that upstream problem.

### Named chains and jumps

Each family supports multiple regular chains under `firewall <family> name`:

```text
set firewall ipv4 name CUSTOM default-action drop
set firewall ipv4 name CUSTOM rule 10 action accept protocol tcp destination-port 22

set firewall ipv4 forward filter rule 10 action jump jump-target CUSTOM

set firewall ipv6 name CUSTOM default-action drop
set firewall ipv6 name CUSTOM rule 10 action accept protocol ipv6-icmp

set firewall ipv6 input filter rule 10 action jump jump-target CUSTOM
```

Named chains have exactly the filter options: `rule`, `default-action`, and
`default-log`, with the same family-specific matches and rule statements. Their
implicit default action is `accept`; `drop` and `reject` are also available. They have no hook
or base-chain policy and receive packets only through a jump. The default verdict
terminates evaluation just as it does in an input/output/forward family chain.

Names are case-sensitive, 1-63 ASCII letters, digits, underscores or hyphens,
starting with a letter or underscore. Kernel names are `ipv4_name_<name>` and
`ipv6_name_<name>`, so identical names in both families and names such as `input`
do not collide with other managed chains.

An enabled rule with `action jump` requires `jump-target`, and the target must
exist in the same family's `name` configuration. `jump-target` with another action
is rejected. Named chains can jump to other named chains; IPv4 raw rules can also
jump to an IPv4 named chain. Global state-policy actions support accept, drop and reject.
Disabled rules remain unrendered, with their cross-field checks deferred until
enabled. Update references when renaming or removing a target. nftables validates
jump loops, stack limits and hook-specific restrictions before the atomic load.

Named-chain log prefixes use `name_<name>` in place of the hook abbreviation,
for example `[ipv4-name_CUSTOM-10-A]` and `[ipv4-name_CUSTOM-default-D]`.
A jump verdict uses `J`, for example `[ipv4-FWD-filter-10-J]`.

Rules support multi-value source/destination addresses (host or prefix), named IP
protocol matches, source/destination ports, connection states, and
`inbound-interface`/`outbound-interface` names,
and the valueless `counter`, `last-used` and `log` statements. Leave `protocol` unset to
omit a protocol restriction; `all` is not a protocol choice. States are `new`,
`established`, `related`, `invalid`, and `untracked`.
The shared `nftables/protocol.yaml.i` include defines protocol choices for both
firewall families, raw rules, and NAT. The `ip-protocol` validator uses a fixed
`frozenset` of supported names, including `tcp`, `udp`, `icmp`, `ipv6-icmp`,
`gre`, `esp`, `ospf`, and `sctp`. Numeric protocol values and aliases outside
that vocabulary are rejected. The `ip` choice denotes protocol number zero,
not a wildcard. Named matches continue to use native `meta l4proto` expressions.
Ports are 1–65535 without leading zeros; ranges use `8000-8100`. nftables combines
overlapping/adjacent ranges and prefixes when loading rules. Repeat a multi-value leaf to add values,
including inside anchored commands. Interface names need not exist; they normally match using quoted `iifname`
and `oifname` sets (see the VRF INPUT behavior below). Names are 1–15 ASCII letters/digits or underscores, optionally
containing dots, colons and hyphens after the first character; wildcards are not supported.

Every enabled rule must specify an action: `accept`, `drop`, `reject`, `jump`,
`continue`, or `return`. Forward filter rules also support `offload`. Either port match
requires one or both of `protocol tcp` and `protocol udp`, with no other protocols;
the local `verify_rule()` identifies the full offending rule path. Global state-policy
states also require an action, limited to `accept`, `drop` or `reject`. Schema validators reject
wrong-family addresses, invalid ranges and rule numbers outside 1–999999 (at most six
digits).

### Interface name prefixes

Rule-level `inbound-interface` and `outbound-interface`, interface-group members,
and zone members accept a trailing `*`:

```text
set firewall group interface-group VPN interface wg*

set firewall ipv4 forward filter rule 10 inbound-interface-group VPN action accept
set firewall ipv6 forward filter rule 10 inbound-interface wg* action accept
set firewall ipv4 forward filter rule 20 outbound-interface not eth1.* action drop
```

These are native prefix matches, so `wg*` includes `wg0`, `wg1`, and interfaces
created later without another commit. Only a nonempty prefix followed by a single
trailing `*` is accepted; this is not shell glob syntax. Negation and repeated
values work as usual. Included interface groups retain their prefixes, counters,
and last-used tracking. Redundant members such as `wg*` and `wg0` in the same
object are emitted once as `wg*`.

User-defined maps and match-groups still require exact interface names.
Wildcard references do not prevent deleting matching interfaces. Direct inbound
rule matches still reapply when a matching interface changes VRF membership.

### Linux link groups and VRF ingress interfaces

Linux link groups are numeric device attributes, distinct from named firewall
`interface-group` sets:

```text
set interfaces dummy dum0 link-group 100

set firewall ipv4 forward filter rule 10 inbound-link-group 100
set firewall ipv4 forward filter rule 10 outbound-link-group not 200
set firewall ipv4 forward filter rule 10 action accept
```

Both matches accept multiple IDs from 0 through 4294967295, including negated
values. They use `meta iifgroup` and `meta oifgroup`. The fields also work in map
and match-group keys, dynamic match-group updates, and `limit per` or connection
limit keys. OUTPUT cannot supply an inbound link group; INPUT and PREROUTING
cannot supply an outbound link group. These checks follow nested named-chain
and verdict-map jumps.

For INPUT rules, an `inbound-interface` referring to an Ethernet or dummy
interface assigned to a VRF uses `meta sdifname` to match that member. A VRF
master name itself still uses `iifname`. Other hooks retain `iifname`, and outbound
matches always retain `oifname`. Negation follows the same selection.

Declare a named interface group's members as VRF-owned with:

```text
set firewall group interface-group MEMBERS interface eth1
set firewall group interface-group MEMBERS vrf

set firewall ipv4 input filter rule 10 inbound-interface-group MEMBERS action accept
```

The flag selects `sdifname` for INPUT consumers without checking current member
existence or membership consistency. Keep ordinary and VRF-member interfaces in
separate matches/groups when using this behavior. A named chain containing such
a match may be called from INPUT, but cannot also be shared with other hooks;
verification asks for separate named chains in that case. Ordinary named chains
remain shareable.

Moving an interface into or out of a VRF updates affected interface-name matches
automatically. Link-group matches use each packet's current interface group.
On INPUT, that is the VRF master's group; PREROUTING sees the member's group.
There is no slave-device group match equivalent to `sdifname`.

### Continue and return

`continue` proceeds to the next rule. `return` leaves the current chain and resumes
the caller after its jump. In a named chain this lets the calling rule set decide
what happens next. In a family chain it returns to nVyR's hook entrypoint.
These are rule actions; default actions and global state policies support accept, drop and reject.

### Flowtables

Flowtables are shared by IPv4 and IPv6 in `inet nvyr_filter`:

```text
set firewall flowtable FAST interface eth0 interface eth1 offload software

set firewall ipv4 forward filter rule 10 action offload
set firewall ipv4 forward filter rule 10 offload-target FAST
set firewall ipv4 forward filter rule 10 connection state established
```

`interface` is multi-valued and requires at least one name or prefix. Exact names
must exist when the firewall script runs. Interfaces created earlier in the same commit are usable.
`commit check` defers host existence checks until commit. Flowtable and interface
references prevent deletion of an interface still used by a flowtable.

The image's Linux 6.18 kernel supports native trailing-prefix devices:

```text
set firewall flowtable FAST interface eth* interface veth*
```

Both exact names and prefixes may be configured before matching devices exist.
The kernel attaches and removes hooks as matching interfaces are created, renamed
or deleted, without a firewall commit. `nft list hooks netdev` shows the current
native attachments.
An older Linux 6.12 image does not gain this support from a package-only nVyR update.

Software offload is the only supported mode and is also the implicit mode when
`offload software` is omitted. The generated flowtable uses ingress priority 0 and
no hardware-offload flag. Its nftables name is `flowtable_<name>`.
An interface may belong to only one configured flowtable at this shared ingress
priority; verification reports overlapping exact names and prefixes before nftables
is called, including overlaps involving future interfaces. Redundant selectors in
one flowtable are collapsed before rendering.

`offload-target` is required with `action offload` and is rejected with other actions.
The target must exist in configuration. Both options are available only under the
IPv4/IPv6 forward filters, not input, output, raw, or named chains. The rule emits
`flow add @flowtable_FAST` without an accept verdict: the current packet continues
through subsequent rules. Once a flow is offloaded, subsequent fast-path packets
bypass the ordinary forwarding rules, as described in the
[nftables flowtable documentation](https://netfilter.org/projects/nftables/manpage.html).
Place offload rules deliberately with respect to filtering and global state policies.

Changed flowtables and their consumers are replaced in one nftables transaction.
Replacement clears cached flows; unchanged flowtables are preserved. Removed
flowtables are found through the effective configuration comparison; recovery also
discovers owned runtime flowtables left by an interrupted apply. Unrelated tables
and unmanaged chains remain untouched. Affected NAT chains share the transaction.

Flowtable instances and the global `state-policy` node are configuration anchors.
The state names are normal child nodes, allowing several policies in one command:

```text
set firewall global-options state-policy established action accept related action accept invalid action drop
```
`offload-target` suggests flowtable names from the current candidate, including
flowtables added earlier in the session and excluding pending deletions.

### Source validation

Source validation checks incoming packets against the reverse route to their
source. It uses nftables in prerouting raw, not the interface's kernel
`rp_filter` setting.

- `strict`: require a usable reverse route through the receiving interface.
- `loose`: require a usable reverse route through any interface.
- `disabled`: skip automatic source validation. This is the default when no
  global mode is configured.

Use independent IPv4 and IPv6 settings when their routing policies differ:

```text
set firewall ipv4 source-validation default loose
set firewall ipv6 source-validation default strict

set firewall ipv4 source-validation interface eth1 mode strict
set firewall ipv6 source-validation interface eth2 mode disabled
```

Alternatively, use `inet` as a single touchpoint for both families:

```text
set firewall inet source-validation default strict

set firewall inet source-validation interface eth1 mode loose
set firewall inet source-validation interface eth2 mode disabled
```

`inet source-validation` cannot coexist with either IPv4 or IPv6
source-validation, including an explicitly disabled setting. IPv4 and IPv6 can
coexist independently. Every interface override requires a `mode` that differs
from its family's global default. Unlisted interfaces inherit that default.
Interface selectors are exact names, with completion suggestions; an interface
does not need to exist when the rules are loaded.

With no global mode, enable validation only on selected interfaces:

```text
set firewall ipv4 source-validation interface eth1 mode strict
set firewall ipv4 source-validation interface eth2 mode loose

delete firewall ipv4 source-validation interface eth2
```

Deleting an override restores the default. Change defaults and overrides in one
commit when needed to avoid leaving a redundant override.

The renderer creates at most two validation rules per applicable raw chain,
using private interface sets for exceptions. These checks precede configured
rules in that chain and only drop failed lookups. Successful and disabled
traffic continues through the normal raw rules. The normal `inet`-before-family
dispatch order still applies: an accepting inet raw rule can bypass subsequent
IPv4/IPv6 chains, including their source validation. Use inet source validation
when it must precede those shared raw rules.

Validation alone creates the necessary prerouting chain and dispatch. Removing
or changing it rebuilds the affected chain and sets atomically, while unrelated
chains retain their counters. Loose validation also passes when the usable
reverse route is a default route; it does not require a more-specific source
prefix. Strict validation is unsuitable for traffic whose intended return route
uses another interface.

VRF traffic is validated on its original member-interface pass. For local
delivery Linux traverses prerouting again on the VRF device; the validation
rules skip that second pass so it cannot override the member's configured mode.
Other raw rules still execute normally. Lookups remain scoped to the packet's VRF.
Configured VRF device names are included automatically in the default's exclusion
set, and VRF changes trigger a firewall reapply through the declarative script watch.
Configure overrides on member interfaces, not on VRF devices.

Every generated drop rule has a counter, shown as `source-validation-strict` or
`source-validation-loose` in the existing operational views:

```text
show firewall ipv4 prerouting raw
show firewall ipv6 prerouting raw
show firewall inet prerouting raw

show firewall inet prerouting raw detail
```

The same source-validation syntax is available under `firewall fail-safe` and
uses its separate table and boot-time lifecycle.

### FIB lookups

FIB matches query routing information using the packet's source or destination
address. They are available in IPv4 and IPv6 filter, raw, and named chains.

```text
set firewall ipv4 prerouting raw rule 10 action drop
set firewall ipv4 prerouting raw rule 10 fib lookup source-address inbound-interface
set firewall ipv4 prerouting raw rule 10 fib result outbound-interface missing

set firewall ipv6 output filter rule 20 action accept
set firewall ipv6 output filter rule 20 fib lookup destination-address
set firewall ipv6 output filter rule 20 fib result route-type local
```

`lookup` is anchored. Select exactly one of `source-address` and
`destination-address`. Optionally add `packet-mark` and one of
`inbound-interface` or `outbound-interface`. No interface constraint is added
implicitly. For reverse-path checks, source-address with inbound-interface
requires the reverse path to use the incoming interface; omitting the interface
allows any reverse path, including a default route.

Select one result category:

- `outbound-interface <name>`: one or more interface names, matched using
  nftables `oifname` so interface recreation does not invalidate stored indices.
- `outbound-interface exists` or `outbound-interface missing`: an existence
  test, which cannot be combined with names or with the opposite test.
- `route-type <type>`: one or more of `unspec`, `unicast`, `local`, `broadcast`,
  `anycast`, `multicast`, `blackhole`, `unreachable`, or `prohibit`.

Repeat the result leaf to add alternative names or route types. Ordinary rule
matches, maps, and match-groups may coexist with the FIB query.

The [nftables FIB restrictions](https://netfilter.org/projects/nftables/manpage.html)
are checked during verification:

- Interface-name and existence results support prerouting, input, and forward.
- Route-type results support all IP hooks. Adding inbound-interface restricts
  them to prerouting, input, and forward; adding outbound-interface restricts
  them to forward, output, and postrouting.
- The outbound-interface lookup input requires a route-type result.

The same restrictions apply to raw and filter priorities. Named chains are
checked against every hook that can reach them, including nested jumps and
verdict-map jumps. Disabled rules do not perform lookups or create jump paths.
An unreferenced named chain has no hook constraint until it is referenced.

Route-type classifies the address; it is not a guarantee of the packet's eventual
forwarding decision. Interface/VRF and policy-routing behavior follows the
kernel's FIB implementation; a mark does not turn an address-type lookup into a
full policy-routing lookup.

### TTL, packet type, and connection status

```text
set firewall ipv4 forward filter rule 20 action drop ttl lt 64 ttl gt 32
set firewall ipv6 forward filter rule 20 action drop ttl eq 1

set firewall ipv4 input filter rule 30 action drop packet-type broadcast

set firewall ipv4 input filter rule 40 action accept connection status offload,confirmed connection status snat,dnat
```

TTL and packet-type matches are available on filter, named and raw chains.
Connection metadata requires a hook after connection tracking.
`ttl` selects `ip ttl` for IPv4 and `ip6 hoplimit` for IPv6, using values 0–255.
`eq` cannot coexist with `lt` or `gt`. The latter are strict comparisons: `gt 63 lt 65`
matches only 64, while `gt 63 lt 64`, `lt 0`, and `gt 255` cannot match and fail verification.

`packet-type` selects one of `broadcast`, `host`, `multicast`, or `other`, rendered
as `meta pkttype`. `connection status` is a multi-value leaf accepting individual
flags or comma-separated groups: `expected`, `seen-reply`, `assured`, `confirmed`,
`snat`, `dnat`, `seq-adjust`, `snat-done`, `dnat-done`, `dying`, `fixed-timeout`,
`helper`, and `offload`.

Each group is an **exact** status combination. Separate values are alternatives:
`connection status offload,confirmed connection status snat,dnat` renders
`ct status == { confirmed | 0x4000, dnat | snat }`. Additional bits prevent a
match unless explicitly included in that group. Group order and repeated flags
do not change the match; equivalent groups are emitted only once. Explicit `==`
keeps single-element sets exact as well.

Groups containing `offload` must also contain `confirmed`. Linux only offloads
confirmed connections and does not admit helper, sequence-adjustment, or dying
connections to the flowtable. Commit rejects those combinations with `offload`;
these restrictions apply within each comma-separated group, not across alternatives.

The renderer uses symbolic expressions instead of calculating masks. Two existing
numeric literals remain necessary in nftables 1.1.7: `helper` is `0x2000` and
`offload` is `0x4000`. That release incorrectly defines these symbols as bit
positions (`0x0d` and `0x0e`), as visible in `nft describe ct status` and in its
compiled comparisons. Using the symbols would change the match. Fully symbolic
rendering for those flags requires a corrected nftables package.

Connection status is distinct from connection state; raw prerouting runs before
the current packet's connection-tracking lookup.

Descriptions are limited to 121 characters and 121 UTF-8 bytes. nftables limits
comments by bytes, so non-ASCII descriptions may reach that limit sooner. Native
nftables quoted strings cannot encode embedded double quotes; descriptions reject
them and control characters. Backslashes are retained literally.

### Marks, DSCP, and TCP MSS

All filter and raw rules support these multi-value matching leaves:

- `packet-mark`: `meta mark`, decimal values 0–4294967295.
- `connection mark`: `ct mark`, decimal values 0–4294967295.
- `dscp`: `ip dscp` or `ip6 dscp`, decimal values 0–63.
- `tcp-mss`: `tcp option maxseg size`, decimal values 0–65535.

Each accepts single values and inclusive ascending `start-end` ranges. Repeat
the leaf to combine them; leading zeros and hexadecimal notation are not accepted.
These use the reusable `integer-range` validator with `allow_range: true`.
MSS only matches the TCP option; it never changes the MSS. nftables infers TCP when
`protocol` is omitted; if a protocol is configured with MSS, it must be only `tcp`.
Connection marks match conntrack state and are generally useful after connection
tracking, rather than at prerouting raw priority before conntrack attaches.

```text
set firewall ipv4 forward filter rule 10 action accept packet-mark 10 packet-mark 20-30
set firewall ipv4 forward filter rule 10 connection mark 1-100 dscp 8-16 dscp 46 tcp-mss 1200-1460
```

**Known limitation:** IPv6 DSCP ranges can load successfully without matching
the expected traffic. Use individual IPv6 DSCP values until the underlying
[nftables issue](../dev/upstream-issues.md#nft-003-ipv6-dscp-interval-sets-fail-packet-matching)
is resolved. IPv4 DSCP ranges are unaffected.

### Modifying packets and connection marks

The anchored `modify` node writes values after the rule's matches and statements,
before its verdict. Ordinary match leaves remain separate: `packet-mark 1` tests
the old mark, while `modify packet-mark 2` replaces it. Multiple setters can share
a rule. Use `action continue` to let later rules evaluate the modified packet.

```text
set firewall ipv4 forward filter rule 10 description "Classify application traffic"
set firewall ipv4 forward filter rule 10 counter

set firewall ipv4 forward filter rule 10 protocol tcp destination-port 443
set firewall ipv4 forward filter rule 10 modify packet-mark 0x20 connection-mark 0x20 dscp af41
set firewall ipv4 forward filter rule 10 action continue
```

Available settings:

- `packet-mark <value>` and `connection-mark <value>` accept decimal or `0x` hexadecimal
  unsigned 32-bit values. They replace the entire mark; they do not copy marks or
  allocate routing-policy marks.
- `dscp <name|0-63>` accepts `be`, `le`, `cs0`–`cs7`, `af11`–`af43` (classes 1–4,
  drop precedences 1–3), `va`, and `ef`. ECN bits are preserved.
- `ttl <0-255>` changes IPv4 TTL or IPv6 hop limit at the current hook. A subsequent
  forwarding step can still decrement it.
- `tcp-mss <1-65535|clamp-to-pmtu>` reduces an existing MSS option. Both modes preserve
  a smaller advertised MSS and do not insert a missing option. Require `protocol tcp`
  and a positive SYN match in every flag alternative; SYN-ACK is allowed. A positive
  match-group can supply the TCP protocol and SYN flags.

Input and forward filter, output filter/raw, and prerouting raw support modification.
Connection marks are excluded from raw chains, which execute before tracking.
Route-based MSS clamping is available only in forward and output. Ingress does not
expose `modify`. Named chains are checked against every caller, including nested jumps,
zone policies and verdict-map targets.

Family-neutral `inet` rules expose marks and MSS. DSCP and TTL remain under `ipv4`
and `ipv6`. The same supported settings are available in the fail-safe firewall.

```text
set firewall ipv4 forward filter rule 20 description "Clamp forwarded TCP handshakes"

set firewall ipv4 forward filter rule 20 protocol tcp tcp-flags syn
set firewall ipv4 forward filter rule 20 modify tcp-mss clamp-to-pmtu
set firewall ipv4 forward filter rule 20 action continue

set firewall ipv6 output filter rule 30 modify ttl 64 dscp ef
set firewall ipv6 output filter rule 30 action continue
```

Setters retain the existing evaluation order. Global state-policy acceptance can
bypass these rules, and offloaded packets can bypass the normal forwarding rules.
The verdict-map lookup runs after setters and therefore sees modified values.
Changing an output packet mark does not request another route lookup; dedicated
policy-based routing is separate from this feature.

Installed modifications appear under `Modify` in `show firewall ... detail`.

### IP and MAC bitmasks

`source-address`, `destination-address`, `source-mac`, and `destination-mac`
are tag nodes. Each address has an optional `mask` leaf. IP masks accept an address
literal of the rule's IP family, including noncontiguous masks. MAC masks accept
MAC address notation. Matching allows zero, broadcast, and multicast MAC addresses,
using `mac: {unicast: false}` without relaxing interface MAC assignment validation.

Without masks, multiple addresses render as an nftables set, as before. If any
address has a mask, configuration requires exactly one address for that field. Source
and destination IP and MAC fields are checked independently. Disabled rules skip
rule checks until re-enabled. A mask cannot be configured without its parent address.
Deleting only `mask` preserves the address as an unmasked match.

```text
set firewall ipv4 input filter rule 20 action drop source-address 192.0.2.129 mask 255.0.255.0
set firewall ipv6 input filter rule 20 action drop source-address 2001:db8::1234 mask ffff:0:ffff::ffff

set firewall ipv4 input filter rule 30 action drop source-mac 02:11:22:33:44:55 mask ff:ff:ff:00:00:00
```

The renderer compares selected bits on both sides, for example
`ip saddr & 255.0.255.0 == 192.0.2.0` or
`ether saddr & ff:ff:ff:00:00:00 == 02:11:22:00:00:00`.
When the IP address includes a prefix, its prefix mask is intersected with the
explicit mask, so bits outside the prefix remain ignored. Ethernet matches only
apply to packets with an Ethernet header; they do not match non-Ethernet traffic.
See the [nftables expression reference](https://netfilter.org/projects/nftables/manpage.html).

## Rule counters and defaults

To enable tracking on every numbered firewall rule, configure:

```text
set firewall global-options counter
set firewall global-options last-used
```

These flags apply to IPv4 and IPv6 filter rules, named-chain rules, raw rules,
and all named map entries (including maps consumed by NAT).
They do not affect ordinary NAT rules, default-action rules, or state-policy
entries. Disabled rules remain omitted. A per-rule flag and its global equivalent
produce only one statement. Removing a global flag leaves explicit per-rule flags
in effect; global flags do not write anything into individual rule configuration.
The `last-used` leaf renders nftables' native `last` statement.

Rules are evaluated in numerical order. The hook default applies if no earlier
rule or zone policy decides the verdict.

The last rule always counts packets and applies the filter's default action
(`accept`, `drop`, or `reject`). `default-log` adds logging directly to that rule after its
counter. Logging has no implicit default. Both rule and default logs receive generated
prefixes: `[family-hook-stage-number-verdict]`, with `default` in place of a rule number.
The stage is `raw` or `filter`, distinguishing output chains with the same rule number.
Hook abbreviations are `INP`, `OUT`, `FWD`, and `PRE`; verdicts are `A`, `D`, `R`, `C`, and `J`
for accept, drop, reject, continue, and jump. For example:

```nft
log prefix "[ipv4-FWD-filter-500-D]" drop comment "500|"
counter log prefix "[ipv4-INP-filter-default-D]" drop comment "default|default-action drop"
```

Use `show firewall` (or `run show firewall` in configuration mode) to inspect
installed rules and counters. See [firewall operational views](nftables-operational-data.md).

## Named maps

See [the map guide](firewall-maps.md) for firewall, SNAT and DNAT examples.

Maps live under `firewall group map ipv4 <name>` or `ipv6 <name>`. Both families
share the table but use distinct generated names (`ipv4_map_<name>` and
`ipv6_map_<name>`). Match fields form a concatenated lookup key; each entry returns
one result. Entry identifiers are labels, not evaluation priorities.

```text
set firewall group map ipv4 SERVICES match source-address protocol destination-port
set firewall group map ipv4 SERVICES result-type verdict

set firewall group map ipv4 SERVICES entry WEB source-address 192.0.2.10 protocol tcp destination-port 443 result action accept
set firewall group map ipv4 SERVICES entry WEB description "Public HTTPS"

set firewall ipv4 forward filter rule 10 map SERVICES
```

`match` is an anchored node with valueless field selectors, so several fields can
be selected in one command. Completion omits selectors already used on that line.
Entries are also anchored: their fields can be supplied in one command. `result` is
repeated when supplying several result children, for example `result action jump
result jump-target TRUSTED`. Referenced named chains must exist in the same family.

Supported key fields are source/destination address, source/destination MAC,
inbound/outbound interface, protocol, source/destination port, state,
connection status, packet-type, packet-mark, connection mark, DSCP, ICMP type,
ICMP code, and TCP flags. Addresses
support exact values, prefixes and ranges; ports, marks and DSCP support exact
values and ranges. Configuration order does not change tuple meanings.

TCP flags use the same `and not` combinations as rule matches (see below).
Their keys require a `protocol` field, with `tcp` in every entry.

Result types are `verdict`, `address`, `port`, and `address-port`. Verdicts support
`accept`, `drop`, `continue`, `return`, and `jump`. Address/port results are consumed
by NAT; firewall rules require verdict maps. A lookup miss continues evaluation.
A consuming rule may add ordinary matches for fields absent from the map key.
For example, a source/destination address map can be restricted to `outbound-interface
eth0` on its consuming rule. A field already in the map key cannot also be configured
on the rule. The map supplies the result, so a separate action, jump/offload target,
translation, or exclusion is not allowed. Normal cross-field checks still apply to
additional matches, including protocol constraints supplied by map entries.
Description, disable, logging and tracking remain available on that rule.

`verify_map()` requires every entry to provide exactly the declared key fields and
result fields. It rejects duplicate/overlapping tuples and missing jump targets.
Transport port keys require `protocol` with TCP, UDP, UDP-Lite, SCTP or DCCP
in every entry. NAT port results remain limited to TCP/UDP.
There may be at most five key fields and 64 bytes of key storage. Concatenated
fields occupy four-byte-aligned slots; oversized keys report a per-field breakdown.

A map-level `description` becomes the map comment (up to 128 UTF-8 bytes).
Entry descriptions remain separate. Tracking is also configured on the map:

```text
set firewall group map ipv4 SERVICES description "Public service policy"
set firewall group map ipv4 SERVICES counter
set firewall group map ipv4 SERVICES last-used
```

Alternatively, `firewall global-options counter` and `last-used` enable tracking
for every map. Global and map options are additive; inheritance does not write
flags into explicit configuration. Every element has its own statistics. Element
comments use `<entry-name>|<description>` and must fit 128 UTF-8 bytes combined.
Rebuilding maps resets their counters and last-used timestamps, like rebuilding rules.

Map references use family-specific dependency registrations and configuration-path
suggestors. Remove consumers before deleting their map. Maps, named chains and NAT
consumers are verified and replaced in one transaction, including deletion, type
changes, commit-confirm rollback and restart recovery.


## ICMP type and code matches

Rules support `icmp-type` and `icmp-code` in IPv4/IPv6 filters, named chains, and
IPv4/IPv6 prerouting and output raw. Type values are nftables symbolic names only;
completion shows each type's numeric value. IPv6 uses its own type-name vocabulary. Codes
are individual decimal values from 0 through 255, without ranges.

```text
set firewall ipv4 input filter rule 10 action accept
set firewall ipv4 input filter rule 10 protocol icmp
set firewall ipv4 input filter rule 10 icmp-type echo-request
set firewall ipv4 input filter rule 10 icmp-code 0

set firewall ipv6 input filter rule 20 action accept
set firewall ipv6 input filter rule 20 protocol ipv6-icmp
set firewall ipv6 input filter rule 20 icmp-type nd-neighbor-solicit
set firewall ipv6 input filter rule 20 icmp-type nd-neighbor-advert
```

Each leaf supports multiple values independently. When both type and code are
configured, exactly one of each is required. An explicit protocol is required:
`icmp` for IPv4 or `ipv6-icmp` for IPv6, without any other protocols. Transport
ports and TCP MSS cannot coexist with ICMP matches.

Maps support scalar ICMP type/code keys for more complex pairings. The map must
include `protocol` in its key, even while empty; every entry must use the
family-specific ICMP protocol. A consuming rule cannot supply this in its place:

```text
set firewall group map ipv4 ICMP_POLICY match protocol icmp-type icmp-code
set firewall group map ipv4 ICMP_POLICY result-type verdict

set firewall group map ipv4 ICMP_POLICY entry ECHO protocol icmp icmp-type echo-request icmp-code 0 result action accept
set firewall group map ipv4 ICMP_POLICY entry UNREACHABLE protocol icmp icmp-type destination-unreachable icmp-code 3 result action accept

set firewall ipv4 input filter rule 30 map ICMP_POLICY
set firewall ipv4 input filter rule 30 inbound-interface eth0
```

Each ICMP key component is one byte (four bytes after concatenation alignment).
IPv6 aliases `mld-listener-done` and `mld-listener-reduction` both mean type 132;
map verification treats them as the same key when checking duplicates.


## ICMP groups

ICMP groups match types alone or type/code pairs. Group names are scoped to IPv4
or IPv6. The group and each `type` instance are anchored:

```text
set firewall group icmp-group ipv4 PING match type

set firewall group icmp-group ipv4 PING type echo-request
set firewall group icmp-group ipv4 PING type echo-reply

set firewall group icmp-group ipv4 ERRORS match type-code

set firewall group icmp-group ipv4 ERRORS type destination-unreachable code 0-3
set firewall group icmp-group ipv4 ERRORS type destination-unreachable code 5
set firewall group icmp-group ipv4 ERRORS type time-exceeded code 0

set firewall group icmp-group ipv4 ERRORS description "Selected ICMP errors"
set firewall group icmp-group ipv4 ERRORS counter
set firewall group icmp-group ipv4 ERRORS last-used

set firewall group icmp-group ipv6 ERRORS match type-code

set firewall group icmp-group ipv6 ERRORS type packet-too-big code 0

set firewall ipv4 input filter rule 10 action accept protocol icmp icmp-group PING
set firewall ipv4 forward filter rule 20 action accept protocol icmp icmp-group ERRORS
set firewall ipv6 input filter rule 30 action accept protocol ipv6-icmp icmp-group ERRORS
set firewall ipv4 output filter rule 40 action drop protocol icmp icmp-group not ERRORS

show firewall group icmp-group ipv4 ERRORS
show firewall group icmp-group ipv6 ERRORS detail
```

`match` is required, even for an empty group. `match type` prohibits `code`;
`match type-code` requires at least one code or inclusive code range beneath every type.
`code` is multi-valued: each configured code or range produces a separate nftables
element paired with its parent type. Adding a code preserves existing codes;
deleting a particular code removes only that selection. Overlapping selections
within one type are rejected. Codes do not support `and`. Types retain their existing
family-specific symbolic choices and numeric descriptions.

`ICMP_KEYMAP` records each supported type's wire number and assigned codes from
the [IANA ICMP registry](https://www.iana.org/assignments/icmp-parameters/) and
[ICMPv6 registry](https://www.iana.org/assignments/icmpv6-parameters/).
`verify_icmp_group()` checks every code in a range. For example,
router-advertisement permits IPv4 codes 0 and 16 individually, but rejects `0-16`
because the intervening codes are unassigned. Two names for the same type cannot
be configured together.

Rules can reference groups in all filter/raw hooks and named chains. They require
the corresponding ICMP protocol, prohibit explicit `icmp-type`/`icmp-code`, and
reject overlapping fields supplied by maps or match-groups. Other independent
matches remain available. Negation excludes complete type/code pairs.

Groups use native nftables sets, inherit global `counter` and `last-used`, and
follow the existing whole-object lifecycle. Dependencies are registered separately
as `firewall-icmp-group-ipv4` and `firewall-icmp-group-ipv6`; deleting a referenced
group is blocked, and changes rebuild all consuming chains, including nested jumps.
Empty groups are valid and match no packets. Dynamic learning is not supported.


## Match-groups

See [the match-group guide](firewall-match-groups.md) for paired permissions,
negative matches, connection fields and dynamic learning examples.

`firewall group match-group ipv4|ipv6 <name>` defines a named nftables set of
packet-field combinations. Each entry must match all of its fields; matching any
entry satisfies the group. Entry names do not establish priority.

Match-groups share the map selectors, scalar entry fields, protocol checks,
five-field/64-byte limits, duplicate/overlap detection, and description limits.
They have no `result-type` or entry `result`. The consuming rule supplies its own
action or translation, or uses a separate map for its result.

```text
set firewall group match-group ipv4 TRUSTED match source-address inbound-interface
set firewall group match-group ipv4 TRUSTED description "Trusted client networks"

set firewall group match-group ipv4 TRUSTED entry OFFICE source-address 192.0.2.0/24 inbound-interface eth0
set firewall group match-group ipv4 TRUSTED entry OFFICE description "Office clients"

set firewall group match-group ipv4 TRUSTED counter
set firewall group match-group ipv4 TRUSTED last-used

set firewall ipv4 forward filter rule 10 match-group TRUSTED action accept
```

`match` and `entry` are anchored just as they are for maps. Tracking is configured
on the group and collected separately for each entry. Global `counter` and
`last-used` settings are inherited. Group descriptions become set comments;
elements use `entry-name|description`. Replacing a group resets its statistics.

A match-group can coexist with a map and explicit rule matches, provided **each
field comes from exactly one source**. For example, the group above supplies source
address and inbound interface, a map can supply destination address, and the rule
can add outbound interface. Any overlap between those sources is rejected with the
conflicting field names. Group membership is checked before rule logging, tracking,
and the map lookup or action. A group miss continues to the next rule.

```text
set firewall group map ipv4 DESTINATIONS match destination-address
set firewall group map ipv4 DESTINATIONS result-type verdict

set firewall group map ipv4 DESTINATIONS entry SERVER destination-address 203.0.113.10 result action accept

set firewall ipv4 forward filter rule 20 match-group TRUSTED map DESTINATIONS outbound-interface eth1
```

Name completion and dependency checks use the configured address family. Delete
references before deleting a group. Empty groups are valid and match no packets.
Match-groups containing ICMP fields still require a protocol key. Port/ICMP
protocol requirements are checked across the rule and its referenced objects.

Match-groups are replaced atomically with firewall rules, maps, and NAT. Deletion,
commit-confirm rollback, and startup recovery use the same pipeline, including
cleanup of owned sets left by an interrupted commit. Generated names are
`ipv4_match_group_<name>` and `ipv6_match_group_<name>`, separate from map names.


## Single-field groups

Use these groups when each member is one value, rather than a combination of
packet fields. Membership is a multi leaf: no entry names or map results are needed.

```text
set firewall group interface-group WAN interface eth0
set firewall group interface-group WAN interface eth1

set firewall group address-group ipv4 TRUSTED address 192.0.2.0/24
set firewall group address-group ipv4 TRUSTED address 198.51.100.10-198.51.100.20

set firewall group address-group ipv6 TRUSTED address 2001:db8::/64

set firewall group mac-group DEVICES address 02:00:00:00:00:01

set firewall group port-group WEB port 80
set firewall group port-group WEB port 443
set firewall group port-group WEB port 8000-8080

set firewall group port-group WEB description "Web services"
```

Interface, MAC, and port groups are shared between IPv4 and IPv6. Address groups
have separate IPv4/IPv6 namespaces. Addresses support individual addresses,
prefixes, and inclusive ranges; ports support individual ports and inclusive ranges.
Overlapping addresses or ports form a union. Empty groups match no packets.
Descriptions become comments on the nftables set.

All four types support valueless `counter` and `last-used` options. Both also
inherit the corresponding `firewall global-options` flags without storing those
flags in explicit group configuration:

```text
set firewall group port-group WEB counter
set firewall group port-group WEB last-used
```

Tracking is maintained per nftables set element, not as a single total for the
group. Overlapping interval members are merged and share the resulting element's
statistics. Rebuilding the set resets its counters and last-used timestamps.

Use a single group name per rule field:

```text
set firewall ipv4 forward filter rule 10 inbound-interface-group WAN
set firewall ipv4 forward filter rule 10 source-address-group TRUSTED
set firewall ipv4 forward filter rule 10 source-mac-group DEVICES
set firewall ipv4 forward filter rule 10 destination-port-group WEB
set firewall ipv4 forward filter rule 10 protocol tcp
set firewall ipv4 forward filter rule 10 action accept
```

The corresponding `outbound-interface-group`, `destination-address-group`,
`destination-mac-group`, and `source-port-group` references are also available.
A group can be reused in either direction, including both directions in the same
rule. Port-group matches require a port-bearing protocol from the rule, a map,
or a match-group.

Each packet field must still have exactly one source. For example,
`source-address-group` conflicts with an explicit `source-address`, a map key
containing `source-address`, or a match-group containing that field. It can coexist
with any of those objects when they supply other fields.

References use completion from the candidate configuration and dependency checks.
Delete consuming references before deleting a group. Interface members also protect
configured interfaces from deletion; they may refer to interfaces not yet created.
Changed groups and their affected firewall/NAT consumers are replaced together.
Full subtree deletion and recovery use the same atomic reference cleanup.


### Including other single-field groups

Use repeatable `include-group` values to reuse configured membership. Direct
members and included groups can coexist. For example, combine several host
categories into one policy object:

```text
set firewall group address-group ipv4 SERVERS address 10.0.10.0/24
set firewall group address-group ipv4 PRINTERS address 10.0.20.0/24
set firewall group address-group ipv4 USERS address 10.0.30.0/24

set firewall group address-group ipv4 ALLOWED_HOSTS description "Hosts permitted to forward"
set firewall group address-group ipv4 ALLOWED_HOSTS counter

set firewall group address-group ipv4 ALLOWED_HOSTS include-group SERVERS
set firewall group address-group ipv4 ALLOWED_HOSTS include-group PRINTERS
set firewall group address-group ipv4 ALLOWED_HOSTS include-group USERS
set firewall group address-group ipv4 ALLOWED_HOSTS address 192.0.2.10

set firewall ipv4 forward filter rule 10 source-address-group ALLOWED_HOSTS action accept

show firewall group address-group ipv4 ALLOWED_HOSTS
```

The same syntax applies to IPv6 addresses, interfaces, MAC addresses, and ports:

```text
set firewall group address-group ipv6 SERVERS address 2001:db8:10::/64
set firewall group interface-group SERVERS interface eth1
set firewall group mac-group PRINTERS address 02:00:00:00:00:01
set firewall group port-group WEB port 80 port 443

set firewall group address-group ipv6 ALLOWED_HOSTS include-group SERVERS
set firewall group interface-group TRUSTED include-group SERVERS
set firewall group mac-group TRUSTED include-group PRINTERS
set firewall group port-group APPLICATIONS include-group WEB port 8443
```

References stay within the same group type and address family. Names are suggested
from that namespace. Groups can include other parent groups, up to **eight
inclusion links**: direct members are depth zero. Verification rejects circular
references and excessive depth, showing the offending inclusion path. Empty
included groups contribute no members.

Generation combines members into the parent's own native set. Duplicate values
are removed, and address/port intervals use the existing merging behavior.
Running and saved configuration retain the `include-group` references. The
operational group view shows the installed combined membership.

Only membership is inherited. Descriptions, counters, last-used, and the
interface-group `vrf` flag remain local to each group; global tracking defaults
still apply normally. A parent tracks its own matching elements independently
of its children. Set `vrf` on the parent itself when its interfaces are VRF-owned
and INPUT matching should use slave interface names.

Dynamic and GeoIP groups cannot include other groups or be included in them.
Their runtime membership changes independently of configuration commits and
would otherwise leave a copied parent stale.

Included groups are protected from deletion or renaming
while referenced. Changes rebuild every dependent parent and its firewall/NAT
consumers, including nested named-chain callers. Unrelated objects retain their
state. Rebuilt objects reset their counters as usual.

Remove one inclusion without removing the others:

```text
delete firewall group address-group ipv4 ALLOWED_HOSTS include-group PRINTERS

commit
```


## Dynamic address and match groups

Address-groups and match-groups can learn exact packet keys. Enable `dynamic`
under the group; its children have these **direct** defaults:
`timeout 10m`, `size 65536`, and `gc-interval 30s`. The defaults apply only when
`dynamic` is configured and are not written into running configuration.

```text
set firewall group address-group ipv4 SEEN dynamic

set firewall group address-group ipv6 SEEN dynamic timeout 1h
set firewall group address-group ipv6 SEEN dynamic size 100000
set firewall group address-group ipv6 SEEN dynamic gc-interval 1m

set firewall group match-group ipv4 FLOWS match source-address protocol destination-port
set firewall group match-group ipv4 FLOWS dynamic timeout 30m

set firewall ipv4 forward filter rule 10 protocol tcp action continue
set firewall ipv4 forward filter rule 10 add-to-group source-address SEEN

set firewall ipv4 forward filter rule 20 protocol tcp action accept
set firewall ipv4 forward filter rule 20 add-to-group match-group FLOWS
set firewall ipv4 forward filter rule 20 add-to-group timeout 5m
```

`add-to-group` is available only in firewall rules. Choose exactly one
`source-address`, `destination-address`, or `match-group` target in the rule's
address family. The target must be dynamic. References participate in normal
suggestions and deletion protection. Match-group updates extract every declared
match field in canonical order; they do not require existing membership.
These extraction fields may also be used by the rule's explicit matches, map,
or match-group: learning is a statement, not an additional match.

A rule emits `update @set { key }`, refreshing the member on every matching
packet. `add-to-group timeout` overrides the group lifetime; otherwise the set's
default applies. Durations accept any positive whole number with `s`, `m`, `h`,
or `d`. Timeout is limited to 18,446,744,073 seconds; garbage collection is
limited to 4,294,967 seconds. `size` accepts 1 through 4,294,967,295 members and
limits learned entries. Garbage collection controls when
expired storage is reclaimed; an expired member no longer matches even before
that collection pass.

Dynamic groups require exact members: prefixes and ranges use an interval
backend that does not support packet-path updates. The existing typed match
fields support exact extraction. Updates automatically restrict transport-port
extraction to port-bearing protocols and ICMP extraction to the family's ICMP
protocol. The rule does not need to repeat that constraint. Explicit or group-supplied
protocol selections must agree with the generated guard. A `protocol` key records
the packet's protocol in each learned entry; it does not itself filter packets.
Prerouting cannot learn an outbound interface before routing has selected it.
Output raw cannot learn an inbound interface. Dynamic groups contain only learned
members: configuring `address` members or match-group `entry` nodes alongside
`dynamic` is rejected during verification. Use a separate static group for
configured members.
Group/global `counter` and `last-used` also track learned
members individually.

Updates execute after ordinary rule matches and before the action or verdict
map lookup. A verdict map miss therefore does not undo an earlier update. When
the set is full and a new key cannot be inserted, nftables skips the rest of
that rule and continues with the next rule; use a separate rule for mandatory
verdicts if learning must not affect their execution.

Learned entries are runtime data, not saved configuration. Unrelated firewall/NAT
commits preserve them. Changing the group definition (including effective inherited
tracking) rebuilds that group and clears its learned members. Recovery, including
commit-confirm expiry and restart, rebuilds owned objects from authoritative
configuration and does not restore learned runtime state.

## Rate and connection limits

`limit` matches traffic within a token-bucket allowance; `limit over` reverses
the match to traffic exceeding it. The rule action remains explicit. For example,
drop excessive echo requests while letting other rules decide whether to accept
requests within the allowance:

```text
set firewall ipv4 input filter rule 10 protocol icmp
set firewall ipv4 input filter rule 10 icmp-type echo-request
set firewall ipv4 input filter rule 10 limit rate packets 10/s burst packets 20 over
set firewall ipv4 input filter rule 10 action drop
```

Without `per`, one allowance is shared by all packets reaching the rule. With
`per`, each distinct key has its own allowance. `and` joins fields into one key:

```text
set firewall ipv4 input filter rule 20 protocol tcp
set firewall ipv4 input filter rule 20 destination-port 22
set firewall ipv4 input filter rule 20 connection state new
set firewall ipv4 input filter rule 20 limit rate packets 6/m burst packets 3 over
set firewall ipv4 input filter rule 20 limit per source-address and destination-port
set firewall ipv4 input filter rule 20 action drop
```

Choose `rate packets` or `rate bytes`, followed by a positive whole quantity
with `/s`, `/m`, `/h`, or `/d`. Byte quantities accept an optional `k`, `m`, or
`g` suffix: `1k` is 1024 bytes, `1m` is 1048576 bytes, and `1g` is 1073741824
bytes. For example, `limit rate bytes 1g/s` is approximately 8.59 Gbit/s.
Packet quantities have no suffix. Rates and bursts must use the same type;
configuring both packet and byte types in either node is rejected.

`burst packets` is a packet count (native default 5). `burst bytes` takes plain
bytes or the same short suffixes, such as `64k`, and
adds that amount to the bucket's rate-sized capacity (native default 0 extra
bytes). Burst allowance replenishes over time; it is not added every period.
Kernel numeric and combined bucket-capacity limits are validated before applying.
These are packet policers, not traffic shapers: packets are matched, not queued.

Available key fields are source/destination addresses, transport ports, MAC
addresses, inbound/outbound interfaces, protocol, packet mark, and connection
mark. Keys use the existing nftables field types and support at most five fields
and 64 bytes including alignment. Port extraction automatically restricts the
rule to port-bearing protocols. Interface and MAC availability is checked by hook,
including through nested named-chain and verdict-map jumps. Conntrack-based limits and keys
are rejected in raw chains.

Subnet grouping masks the packet address before forming the key. The user
supplies a prefix length, not a network address. Both directions and IPv4/IPv6
are supported:

```text
set firewall ipv4 input filter rule 20 limit source-prefix-length 24

set firewall ipv6 forward filter rule 30 limit rate bytes 1m/s burst bytes 64k over
set firewall ipv6 forward filter rule 30 limit per source-address and destination-address
set firewall ipv6 forward filter rule 30 limit source-prefix-length 64
set firewall ipv6 forward filter rule 30 limit destination-prefix-length 64
set firewall ipv6 forward filter rule 30 action drop
```

`connection limit over` matches when the tracked count exceeds a threshold.
This counts conntrack connections, not application logins. With `connection state new`,
existing sessions can continue while additional connections are blocked:

```text
set firewall ipv4 input filter rule 40 protocol tcp
set firewall ipv4 input filter rule 40 destination-port 22
set firewall ipv4 input filter rule 40 connection state new
set firewall ipv4 input filter rule 40 connection limit over 5
set firewall ipv4 input filter rule 40 connection limit per source-address
set firewall ipv4 input filter rule 40 action drop
```

Connection limits support the same `per` combinations and prefix-length options.
These keys still inspect packet fields: `per source-address` uses the packet's
source address, not the conntrack original source address.
They follow conntrack expiration and deliberately have no configurable element
timeout. Rate limits can use `limit timeout 10m`; the timeout must be at least
the full bucket refill time. The default is the greater of 60 seconds and that
refill time. Inactivity expiry safely discards a fully replenished allowance.

Per-key limits allocate private dynamic sets with a default capacity of 65536
keys. Configure `limit size` or `connection limit size` to change it. These sets
are separate from user-defined firewall groups. At capacity, a new key cannot
be tracked and nftables skips the remaining rule statements; subsequent rules
and the chain's default action therefore determine its outcome. An `over ...
drop` rule alone is not a fail-closed policy when its set fills.

Limits run after ordinary matches and before logging, counters, group updates,
and verdicts. A later failed match or verdict-map miss does not undo state already
updated. Multiple limits on one rule are sequential matches. Unrelated commits
preserve limit state. Rebuilding a chain resets its private limits atomically;
removing a limit or chain removes its sets. Recovery rebuilds limit state rather
than attempting to restore runtime buckets or connection-count lists.

## Shared limit and counter groups

Limit groups share one allowance across their referencing rules. They use the
same packet/byte rate, burst, `over`, `per`, prefix-length, size and timeout
settings as inline limits. Separate IPv4 and IPv6 namespaces keep address keys
unambiguous:

```text
set firewall group limit-group ipv4 LOGIN description "Shared login attempts"

set firewall group limit-group ipv4 LOGIN rate packets 10/m
set firewall group limit-group ipv4 LOGIN burst packets 5
set firewall group limit-group ipv4 LOGIN per source-address
set firewall group limit-group ipv4 LOGIN over

set firewall ipv4 input filter rule 10 protocol tcp destination-port 22 limit group LOGIN action drop
set firewall ipv4 input filter rule 20 protocol tcp destination-port 443 limit group LOGIN action drop
```

Both rules update the same allowance for each source address. Without `per`, all
matching traffic shares one bucket. A rule cannot combine `limit group` with
inline limit settings. Hook restrictions on the group's key fields apply to
every consumer, including indirect jumps through named chains.

Counter groups are family independent and may be used by firewall and NAT rules:

```text
set firewall group counter-group DROPS description "Combined policy drops"

set firewall ipv4 input filter rule 10 counter group DROPS
set firewall ipv4 input filter rule 20 counter group DROPS
set firewall ipv6 input filter rule 10 action drop counter group DROPS
```

Plain `counter` still creates a private rule counter. An explicit counter group
takes precedence over the global anonymous-counter setting. Group totals are
shown by `show firewall group counter-group DROPS`; individual rule views do not
misrepresent the shared total as a private rule count.

Shared objects survive consumer-only chain rebuilds. Changing a group rebuilds
that object and all dependent chains atomically; unchanged objects retain their
counts and allowances. Dependency checks protect referenced groups from deletion.
Recovery rebuilds shared state along with the other managed nftables objects.

## Kernel logging options

Plain `log` keeps the generated rule prefix and native warning severity. Set a
severity or additional header details beneath it:

```text
set firewall ipv4 input filter rule 10 log level info
set firewall ipv4 input filter rule 10 log flags tcp-sequence and tcp-options
```

Levels are `emerg`, `alert`, `crit`, `err`, `warn`, `notice`, `info`, and `debug`.
Flags are `tcp-sequence`, `tcp-options`, `ip-options`, `skuid`, `ether`, and `all`.
Use `and` to join flags with completion; `all` cannot be combined with individual
flags. These options are also available on NAT rules. Logging does not change a
rule's verdict. NFLOG, packet snap length and queue thresholds are not exposed.

For sampled logging with unconditional drops, put the limited logging rule in a
named chain and return to a separate drop rule. A limit on the drop rule itself
would limit the drops as well as the logging.


## Reject responses

Select the response independently of the action. An explicit rule setting overrides
`firewall global-options reject-response`; without either, nftables uses its native
port-unreachable default. Inherited settings are never written into configuration.

```text
set firewall global-options reject-response admin-prohibited

set firewall ipv4 input filter rule 10 action reject
set firewall ipv4 input filter rule 10 reject-response port-unreachable

set firewall ipv4 input filter rule 20 protocol tcp action reject reject-response tcp-reset

set firewall ipv6 input filter rule 30 action reject reject-response policy-fail

set firewall ipv4 input filter default-action reject

set firewall global-options state-policy invalid action reject
```

Global responses are `port-unreachable`, `admin-prohibited`, `no-route` and
`host-unreachable`. These use ICMPX to select the appropriate IPv4/IPv6 response.
Rule responses additionally support `tcp-reset` in either family; IPv4 supports
`net-unreachable`, `prot-unreachable`, `frag-needed`, `net-prohibited` and
`host-prohibited`; IPv6 supports `addr-unreachable`, `policy-fail` and `reject-route`.

`reject-response` requires an explicit `action reject`. TCP resets require a
TCP-only protocol match, directly or through a positive match-group. The global
setting cannot select TCP resets or family-specific responses. It applies to
rejecting numbered rules, named-chain rules, default actions and state policies.
Reject is supported in input, forward, output and prerouting, including the raw
stages. Hook verification follows nested jumps and verdict-map jumps.

Reject is a statement rather than a verdict-map value, so rejecting state policies
are generated as ordinary counted rules. Accept/drop state policies retain their
verdict map. Changing the global response rebuilds affected chains, including
inheriting default actions and state policies, while preserving unrelated objects.

## TCP flags and packet length

TCP flags support `fin`, `syn`, `rst`, `psh`, `ack`, `urg`, `ecn`, and `cwr`.
Use `and` to combine requirements and `not` to require a flag to be clear:

```text
set firewall ipv4 input filter rule 10 protocol tcp
set firewall ipv4 input filter rule 10 tcp-flags syn and not ack and not fin and not rst
set firewall ipv4 input filter rule 10 tcp-flags rst
set firewall ipv4 input filter rule 10 action accept
```

Each repeated `tcp-flags` value is an alternative. Unmentioned bits do not affect
the match. Overlapping alternatives still execute the rule's counter, log and
action only once. A flag cannot appear twice or in both polarities within one
combination. Completion remains available after both `and` and `not`.
Deleting a complete combination removes only that alternative.

Maps and match-groups accept the same expressions, with one combination per entry:

```text
set firewall group map ipv4 TCP_ACTIONS match protocol tcp-flags
set firewall group map ipv4 TCP_ACTIONS result-type verdict

set firewall group map ipv4 TCP_ACTIONS entry INITIAL protocol tcp tcp-flags syn and not ack result action accept

set firewall ipv4 input filter rule 20 map TCP_ACTIONS

set firewall group match-group ipv6 TCP_INITIAL match protocol tcp-flags

set firewall group match-group ipv6 TCP_INITIAL entry INITIAL protocol tcp tcp-flags syn and not ack

set firewall ipv6 input filter rule 20 match-group TCP_INITIAL action accept
```

Both group kinds require `protocol` in their match fields and `tcp` in each
entry. Ordinary rules require `protocol tcp`, directly or supplied by their
group. Conflicting explicit and group fields remain invalid. Overlapping group
entries are rejected. A combination can expand into several native keys to
preserve unspecified flags; operational output combines their statistics into
one logical entry. Dynamic match-groups learn the complete flag byte, and their
size limit includes expanded configured keys.

Packet length is the number of bytes in the IP packet, including its IP header.
It accepts individual values and inclusive ranges from 0 through 4294967295.
Repeated positive values are alternatives; exclusions further restrict the match:

```text
set firewall ipv4 input filter rule 30 packet-length 40 packet-length 100-200
set firewall ipv4 input filter rule 30 packet-length not 150
set firewall ipv4 input filter rule 30 action drop
```

Both matches are available in IPv4 and IPv6 rules, including raw and named chains.
Packet length uses `meta length`; kernel packet aggregation can affect the size
observed at a hook. TCP flag requirements apply only where a TCP header is present.

## Connection tracking matches

The anchored `connection` node groups matches on the tracked connection, separately
from the packet's current headers. State, status and mark use `connection state`,
`connection status` and `connection mark`.

For enabled rules, `connection` must contain a match or connection limit. Configured
`original`, `reply`, and `total` sections must each contain a match; empty sections
are rejected during `commit check` and commit. Settings may be entered across
multiple commands before validation.

```text
set firewall ipv4 forward filter rule 10 connection state established
set firewall ipv4 forward filter rule 10 connection direction original
set firewall ipv4 forward filter rule 10 connection protocol tcp
set firewall ipv4 forward filter rule 10 connection original destination-address 203.0.113.10
set firewall ipv4 forward filter rule 10 connection original destination-port 443
set firewall ipv4 forward filter rule 10 action accept
```

After DNAT, this still matches the public destination originally contacted.
Packet `destination-address` and `destination-port` instead match the translated
packet. The `reply` tuple is the reverse direction as stored by conntrack, including
any NAT transformations.

General fields:

- `state`: new, established, related, invalid, untracked.
- `status`: the exact status combinations described above.
- `mark`: decimal marks or ranges, 0–4294967295.
- `direction`: original or reply.
- `family`: ipv4 or ipv6, consistent with the rule or group family.
- `protocol`: named transport protocol of the tracked tuple.
- `zone`: zone numbers or ranges, 0–65535.
- `id`: transient kernel connection identifiers or ranges, 0–4294967295.
- `helper`: assigned conntrack helper name, up to 15 characters.
- `label`: numeric bit positions 0–127, joined with `and`.
- `expiration eq|lt|gt`: remaining lifetime, using `s`, `m`, `h` or `d`.

`original` and `reply` each provide `source-address`, `destination-address`,
`source-port`, `destination-port`, `zone`, `packets`, `bytes`, and
`average-packet-size`. Address values accept addresses, prefixes and ranges;
ports and zones accept individual values or ranges. Ports require a positive
`connection protocol` of tcp, udp, udplite, sctp or dccp. This is distinct from
the packet-level protocol, including for related ICMP errors.

`total` provides `packets`, `bytes` and `average-packet-size` for both directions.
All accounting fields use `eq`, `lt` or `gt`. Counts are nonnegative 64-bit values;
byte quantities also accept `k`, `m` or `g` using powers of 1024. Expiration accepts
whole seconds up to 4294967 seconds. Equality cannot be mixed with bounds, and
strict bounds must leave at least one possible value.

```text
set firewall global-options connection-accounting

set firewall ipv4 forward filter rule 20 connection original bytes gt 1m
set firewall ipv4 forward filter rule 20 connection total packets gt 100
set firewall ipv4 forward filter rule 20 connection expiration lt 30s
set firewall ipv4 forward filter rule 20 action drop
```

Accounting must be explicitly enabled. Apply sets `net.netfilter.nf_conntrack_acct`;
removing the setting disables accounting for subsequently created connections.
Existing connections do not gain missing historical counters. Commit check does
not change the sysctl, and failed nftables applies restore its previous value.

Scalar rule matches are multi-value alternatives and support `not`; comparison
nodes support `eq not`. Labels require every joined bit, allow unrelated bits,
and treat repeated values as alternatives:

```text
set firewall ipv4 forward filter rule 30 connection label 1 and 127
set firewall ipv4 forward filter rule 30 connection label 4
set firewall ipv4 forward filter rule 30 connection label not 6 and 7
set firewall ipv4 forward filter rule 30 action accept
```

This requires `(1 AND 127) OR 4`, excluding connections containing both 6 and 7.
Simple all/any tests stay compact. Complex alternatives expand only within the
tested bits, with verification capped at 4096 generated values.

Maps and match-groups use the same nested selectors and scalar entry values.
They support the connection fields above except label predicates. Comparison
fields become ordinary exact set keys rather than `eq|lt|gt` nodes.
Accounting keys require the global accounting setting, even in unused groups.

```text
set firewall group match-group ipv4 PUBLIC_WEB match connection protocol original destination-address destination-port

set firewall group match-group ipv4 PUBLIC_WEB entry HTTPS connection protocol tcp original destination-address 203.0.113.10 destination-port 443

set firewall ipv4 forward filter rule 40 match-group PUBLIC_WEB action accept
```

Groups with connection ports must include `connection protocol` in their key.
Packet and connection fields remain distinct for conflict checks. Native types
are used where available; keys needing fixed-width integer/string metadata use
`typeof`. Dynamic groups can learn these keys through the existing `add-to-group`
mechanism.

Raw hooks execute before tracking. Only invalid/untracked state tests are
accepted there; other connection metadata is rejected, including through nested
jumps and group lookups or updates.

**Known nftables 1.1.7 display limitation:** its listing code can merge adjacent
opposite comparisons on different conntrack fields. For example,
`ct expiration < 10s ct original bytes > 1024` is programmed correctly in the
kernel but may be listed incorrectly as a byte range. Both native text and JSON,
and consequently operational output based on that JSON, can be affected.
nVyR does not reorder predicates or fabricate a corrected listing. Resolving
the listing defect requires an upstream nftables fix.

## Application connection helpers

Enable standard-port helpers for FTP, TFTP, or SIP:

```text
set firewall global-options connection-tracking helper ftp
set firewall global-options connection-tracking helper tftp
set firewall global-options connection-tracking helper sip
```

FTP uses TCP/21, TFTP uses UDP/69, and SIP uses TCP and UDP/5060. Each option
applies to IPv4 and IPv6. These are explicit assignments: enabling a helper does
not enable the kernel's automatic helper selection or open a firewall port.
Helpers inspect their application's control traffic to track related connections.

One named map, `conntrack_helpers`, looks up the transport protocol and destination
port. INPUT, FORWARD, and OUTPUT assign helpers to new connections in their
original direction, after global state/flowtable policies and before user inet
rules and IPv4/IPv6 dispatch. Assignment continues into those rules; a map miss
also continues. Global verdicts reached first remain authoritative. Raw and
ingress chains have no helper assignment.

For example, enable FTP tracking and allow its control and related traffic:

```text
set firewall global-options connection-tracking helper ftp
set firewall global-options state-policy established action accept
set firewall global-options state-policy related action accept

set firewall ipv4 forward filter rule 10 inbound-interface eth1 protocol tcp destination-port 21 action accept
set firewall ipv4 forward filter default-action drop
```

The package supplies module soft dependencies so native helper autoloading also
loads the corresponding NAT helper. NAT translation remains configured through
the normal NAT rules. Plaintext application helpers cannot inspect encrypted FTP
or SIP payloads. Disabling a helper prevents subsequent assignment; it does not
clear existing connections or their expectations.

`show conntrack detail` exposes assigned helper names. `show firewall` includes a
`global-helpers` row in each applicable state-policy section. The internal helper
map has no element counters: the supported kernel does not update them on object
map lookup; see [upstream investigation](../dev/upstream-issues.md#linux-helper-001-object-reference-map-counters-do-not-increment).
Fail-safe configuration does not expose these global connection-tracking settings.

## Byte quotas

Quotas match cumulative traffic volume, independently of packet/byte rate limits.
Inline quotas belong to one rule:

```text
set firewall ipv4 forward filter rule 10 quota bytes 10g over
set firewall ipv4 forward filter rule 10 action drop
```

Both `over` and `until` are available and mutually exclusive. `until` is the
implicit default: it matches while the packet fits within the allowance.
`over` matches packets that take consumption above the allowance. The quota
accounts for each packet reaching it, including packets for which its condition
does not match. The rule action remains separate.

Amounts accept whole bytes or lowercase `k`, `m`, and `g`, using powers of 1024.
The range is 0 through 9223372036854775807 bytes after conversion. Zero provides
no allowance. There is no time interval or automatic refill.

Named quota groups share one allowance across rules and IP families:

```text
set firewall group quota-group GUESTS bytes 100g over
set firewall group quota-group GUESTS description "Combined guest traffic"

set firewall ipv4 forward filter rule 20 quota group GUESTS action drop
set firewall ipv6 forward filter rule 20 quota group GUESTS action drop
```

A group reference cannot be combined with inline `bytes`, `over`, or `until`.
A referenced group cannot be deleted. Changing a group
rebuilds that object and its consuming chains, including nested jump callers,
in the same nftables transaction.

Unchanged named quotas retain usage across unrelated commits and consumer-chain
rebuilds. Rebuilding the quota itself resets usage. Inline quotas reset when
their owning chain is rebuilt. Runtime usage is not saved in the configuration
and is reset during full firewall recovery or reboot.

```text
show firewall group quota-group
show firewall group quota-group GUESTS
show firewall group quota-group GUESTS detail

clear firewall quota GUESTS
clear firewall counter TOTAL
```

Quota tables show mode, allowance, used bytes, remaining bytes, exhaustion and
description. Rule detail output includes inline quota parameters and usage or
the referenced quota name. nftables caps reported used bytes at the allowance;
this is not an unlimited traffic counter.

The `clear` commands require net-admin or administrator access and reset
only the named quota or counter group. They neither change configuration nor
commit or save anything. In configuration mode, prefix them with `run`.

Only packets reaching a quota consume it. Earlier accepts and flow offloading
can bypass it; multiple references reached by the same packet consume the
shared allowance repeatedly.

## Offloaded packet accounting

`counter` on a flowtable synchronizes accelerated packet and byte totals into
connection tracking. Enable connection accounting before establishing the flows
whose totals you want to inspect:

```sql
set firewall global-options connection-accounting

set firewall flowtable FAST interface eth0 interface eth1 counter
```

This is independent of the counter following the global `flow add` statement:
that rule counts successful enrollments, while flowtable accounting counts
accelerated traffic. `show conntrack ... detail` exposes the per-connection totals;
there is no aggregate packet counter owned by the flowtable object. nftables 1.1.7
shows the `counter` setting in its text listing but omits it from JSON listings.

## Global flowtable enrollment

```text
set firewall flowtable FASTPATH interface eth0 interface eth1 offload software

set firewall global-options state-policy established action accept
set firewall global-options flowtable FASTPATH
```

This enrolls established forwarded TCP/UDP connections before the global
established-state accept, for both IPv4 and IPv6. New connections still pass
through normal rules and zone policies. INPUT and OUTPUT do not enroll flows.
The flowtable must exist and the established state policy must accept; verification
rejects other combinations. The enrollment statement itself adds no accept verdict.

The existing flowtable selects participating interfaces. Registered references
prevent deleting it while the global option uses it. Changing its devices or
the selected target replaces the affected forward entrypoint atomically.
Individual rule-level offload remains available for selective enrollment.
Packets using the flowtable fast path bypass subsequent normal forwarding
evaluation, including its counters, logging, and limits.

## Transport-port matching

Packet source/destination ports support `tcp`, `udp`, `udplite`, `sctp`, and
`dccp` in both address families. The same protocols work with port groups,
map/match-group port keys, dynamic updates, and per-port limits. Individual
ports, ranges, repeated alternatives, and exclusions retain their existing
behavior. TCP flags and MSS remain TCP-only.

```text
set firewall ipv4 input filter rule 10 protocol sctp destination-port 3868 action accept
set firewall ipv6 input filter rule 20 protocol udplite destination-port 53098 action accept
```

Explicit port matches require a positive protocol selection. Dynamic updates
and per-port limits supply their own transport guard when none is configured.
NAT port translation and port-valued map results remain restricted to TCP/UDP;
this change does not expand flow-offload eligibility.

## Clearing learned group members

Network administrators can remove runtime membership without rebuilding the set
or its consuming chains. These commands use running configuration, including when
called with `run` from configuration mode:

```text
clear firewall group address-group ipv4 BLOCKED member 192.0.2.10
clear firewall group address-group ipv4 BLOCKED learned

clear firewall group address-group ipv6 BLOCKED member 2001:db8::10
clear firewall group address-group ipv6 BLOCKED learned

clear firewall group match-group ipv4 FLOWS member source-address 192.0.2.10 protocol tcp destination-port 443
clear firewall group match-group ipv4 FLOWS learned

clear firewall group match-group ipv6 FLOWS member source-address 2001:db8::10 protocol tcp destination-port 443
clear firewall group match-group ipv6 FLOWS learned
```

A match-group member requires exactly the fields selected by that group, in any
CLI order. Completion offers those fields and their ordinary validators, hints
and choices. Nested fields retain their configuration syntax, such as
`connection original destination-address 203.0.113.10`. Values must describe one
exact key, not a prefix, range or partially specified combination. For `tcp-flags`,
name the flags present using `and`, or enter the exact byte value (0 for no flags).
Flags omitted from this runtime selector are clear, unlike a rule's masked match.

`member` destroys only that key; an already expired or absent member is harmless.
`learned` flushes the selected set's elements. Configd rejects static groups and
cleanup during a commit, rollback or recovery. No commit or save is required, and
configuration and other members' state remain unchanged after a single-key clear.
Flushing removes every element's counters/last-used state along with membership,
but preserves the set, chains and rule counters. Packet learning remains active,
so subsequent traffic can recreate cleared members immediately.

## Applying and recovering changes

Firewall and NAT changes are applied together atomically: packets see the old
ruleset or the new one. A rejected update leaves the previous rules installed.
Unchanged objects retain counters and learned members; replacing an object resets
its runtime state. Recovery rebuilds the configured ruleset and resets that state.
Use `save` to retain committed configuration across reboot.
