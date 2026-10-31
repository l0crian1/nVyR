# IPv4 NAT

For implementation and testing, see the [developer guide](../dev/nat.md).

For complete map-based SNAT and DNAT scenarios, see [firewall maps](firewall-maps.md).
For reusable combinations that gate a translation, see
[match-groups](firewall-match-groups.md#8-allow-nat-only-for-approved-clientcollector-combinations).

## Operational views

```text
show nat source
show nat source rule 10
show nat source detail
show nat source rule 10 detail

show nat destination
show nat destination rule 20 detail

show nat translations
show nat source translations
show nat destination translations

show nat translations ipv4 protocol tcp state established
show nat destination translations destination-address 198.51.100.20 detail
```

Rule views read installed nftables state and preserve evaluation order. Disabled
or unapplied candidate rules do not appear. The summary includes the action,
translation address/port or map, available counters, last use and description.
`detail` shows all normalized rule fields in headerless tables. NAT counters
measure packets evaluated by the NAT rule, normally the first packet of a
connection; they are not total traffic counters for the resulting translation.

Translation views read the live conntrack table. They show original and translated
source/destination endpoints, protocol, NAT type, transport state and remaining
timeout. A connection with both SNAT and DNAT appears once in the combined view
and is included in both directional views. Filters use **original addresses before
NAT**. Both families are inspected by default, even though nVyR currently exposes
only IPv4 NAT configuration. Runtime entries are not attributed to rule numbers:
conntrack does not retain that relationship, and rules may have changed since the
connection was created.

The same family, protocol, state, address and detail filters are available under
[`show conntrack`](conntrack-operations.md). ## Configuration

Source NAT runs in postrouting; destination NAT runs in prerouting:

```text
set nat source rule 10 source-address 192.0.2.0/24 outbound-interface eth0 translation address masquerade

set nat destination rule 10 inbound-interface eth0 protocol tcp destination-port 443 translation address 192.0.2.10 translation port 8443

commit
save
```

Rules are anchor-capable and ordered numerically using the firewall convention:
numbers 1 through 999999 with at most six characters. Both directions support
multi-value `source-address`, `destination-address`, `source-port`,
`destination-port` and `protocol` matches. Repeat the leaf name for additional values.
Addresses accept IPv4 hosts/prefixes; match ports accept individual ports and
ascending ranges. Protocols use the same named `ip-protocol` validator and choices
include as firewall rules; numeric values are not accepted. Leave `protocol` unset
to match without a protocol restriction. Ports require an
explicit nonempty selection of TCP and/or UDP, including translation ports.

`outbound-interface` is available only for source NAT and `inbound-interface` only
for destination NAT. Both are multi-value interface-name matches and may reference
interfaces that do not exist yet, with the same matching behavior as firewall rules.

## Translation

Each enabled rule needs `translation address`, `translation port`, or `exclude`.
Translation address/port are each single-valued; ranges describe contiguous pools.

```text
set nat source rule 20 translation address 203.0.113.10
set nat source rule 30 translation address 203.0.113.0/24

set nat destination rule 20 translation address 192.0.2.10-192.0.2.20
set nat destination rule 20 protocol tcp translation port 8000-8100
```

Address prefixes must have no host bits. They become inclusive address pools:
`203.0.113.0/24` is passed directly to nftables as a CIDR pool, including both endpoints.
This is pool selection, not one-to-one prefix mapping. An explicit range must be
ascending and entirely IPv4. The generic `ipv4-address`, `network`, `ip-range` and
`list` validators compose these forms; masquerade is permitted only by the source
address definition. The shared `port` validator handles port ranges and rejects
leading zeros. Port strings are rendered unchanged; nftables normalizes anonymous
address/port sets.

Source NAT renders `snat ip to ...`, destination NAT `dnat ip to ...`, and
`translation address masquerade` selects the outgoing interface's address.
Masquerade can also specify a translation port/range. A port-only translation
renders `snat to :PORT` or `dnat to :PORT` and leaves the address unchanged.

NAT does not assign pool addresses to interfaces, arrange upstream reachability,
enable proxy ARP, or create firewall permits. Those remain separate configuration
responsibilities. Destination NAT here covers incoming traffic, not locally
generated traffic requiring an output NAT hook.

## Mapping options

```text
set nat source rule 10 protocol tcp protocol udp
set nat source rule 10 translation port-mapping fully-random
set nat source rule 10 translation persistent
```

`translation port-mapping` accepts `default`, `random` or `fully-random`. Omission
or `default` emits no flag; the other values emit their nftables flags. Random modes
require TCP and/or UDP in this initial CLI. They are mutually exclusive choices.
`translation persistent` is a separate valueless flag requiring a translation
address. It requests stable translated address selection for a client across
connections; it does not preserve connections across reboot or guarantee a fixed port.

The interface follows the [nftables NAT statement documentation](https://netfilter.org/projects/nftables/manpage.html).
On kernels 5.0 and newer, `random` and `fully-random` have the same behavior; both
spellings remain available. Translation maps are supported as described below;
prefix-to-prefix mapping and redirect are not exposed by this CLI.

## Exclusion, disable, descriptions and rule observations

```text
set nat source rule 5 destination-address 198.51.100.0/24 exclude
set nat source rule 10 description "Internet egress" log counter last-used

set nat destination rule 20 disable
```

An `exclude` rule emits `return`, exiting the family NAT chain before later rules
can translate the matching connection. It cannot also contain a `translation`
subtree, even an empty one; delete that subtree when converting a rule to an
exclusion. An exclusion does not override unrelated NAT chains maintained by
other software.

Disabled rules remain configured and value-validated, but are omitted from
rendering and skip lifecycle completeness checks. Descriptions follow firewall
comment limits: 121 characters and UTF-8 bytes, without control characters or
double quotes. Comments use `number|description`.

Logging precedes the translation or return statement. Prefixes use the existing
family/hook/number/action structure: `[ipv4-POST-10-S]` for SNAT,
`[ipv4-PRE-10-D]` for DNAT, `M` for masquerade and `E` for an exclusion.
NAT chains process the first packet that establishes a connection's NAT mapping;
logging is not a per-packet audit of the entire connection.

Both rule types also accept valueless `counter` and `last-used` leaves, including on
exclusions. `counter` records matching packets/bytes and `last-used` records the last
match time. They use the same nftables statements as firewall rules, before the
translation or `return`. Because NAT evaluates new connection mappings, these
describe NAT rule evaluations rather than every packet in an established flow.
Replacing NAT chains on commit resets both observations. Disabled rules emit neither.

## Translation maps

NAT rules can reference an IPv4 [firewall map](firewall.md#named-maps) with an
`address`, `port`, or `address-port` result:

```text
set firewall group map ipv4 PORT_FORWARD match inbound-interface
set firewall group map ipv4 PORT_FORWARD match protocol
set firewall group map ipv4 PORT_FORWARD match destination-port
set firewall group map ipv4 PORT_FORWARD result-type address-port

set firewall group map ipv4 PORT_FORWARD entry WEB inbound-interface eth0 protocol tcp destination-port 443 result address 10.0.0.10 result port 8443

set nat destination rule 10 map PORT_FORWARD
```

The map supplies its key matches and translation. The rule may add explicit matches and a `match-group` for
fields absent from the map key, but cannot also specify `translation` or `exclude`.
Source NAT requires `outbound-interface` on the rule, map, or match-group; destination NAT
requires `inbound-interface` on one of those sources, and cannot match `outbound-interface`
before routing. Port lookups/results require a
TCP or UDP protocol field in every entry. Map-level tracking also works for NAT
consumers and inherits firewall global tracking options. Ordinary NAT rules retain
their own tracking options.

## Single-field groups

NAT also accepts the [single-field firewall groups](firewall.md#single-field-groups).
Use `inbound-interface-group` for destination NAT or `outbound-interface-group` for
source NAT, matching the existing explicit interface syntax. Address groups must
be IPv4. Source/destination address, MAC, and port group references can coexist
with maps and match-groups when their packet fields do not overlap.

```text
set firewall group interface-group WAN interface eth0
set firewall group address-group ipv4 CLIENTS address 192.0.2.0/24
set firewall group port-group WEB port 443

set nat destination rule 10 inbound-interface-group WAN
set nat destination rule 10 source-address-group CLIENTS
set nat destination rule 10 destination-port-group WEB
set nat destination rule 10 protocol tcp
set nat destination rule 10 translation address 10.0.0.10
set nat destination rule 10 translation port 8443
```

A group-supplied interface satisfies NAT's interface requirement. Port groups
require a port-bearing protocol constraint (TCP, UDP, UDP-Lite, SCTP or DCCP),
including when the protocol comes from a map or match-group. Port translation
still requires TCP or UDP. Group membership is checked before logging, counters, or translation.

## Applying changes

Firewall and NAT changes share one atomic update. A failed update leaves their
changes pending, and confirmed rollback restores them together. Existing connection
translations survive rule changes until they expire; changed rules govern new
connections. nVyR does not flush all tracked connections on every commit.
