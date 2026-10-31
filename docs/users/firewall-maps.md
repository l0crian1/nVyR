# Firewall maps: choose a result from packet fields

A map answers: **"For this combination of packet fields, what should I do?"**
Each entry contains the fields to look up and the result to use. A firewall map
can accept, drop or select a named policy chain. A NAT map can select the translated
address, port, or both.

A [match-group](firewall-match-groups.md) answers a different question: **"Is this
combination in the group?"** Its entries have no result; the consuming rule supplies
one action for all matching entries. Use a map when the result varies by entry.

## Why a lookup instead of 250 individual rules?

Suppose 250 customer/service combinations each select a policy. With 250 ordinary
rules, a packet matching the last rule can pass through 249 unsuccessful rule
checks first. A packet matching none may traverse all 250. With a map, one rule
extracts the selected fields and performs a lookup among 250 entries. Adding a
customer adds an entry, not another sequential rule for every packet to visit.

For exact-key hash lookups, the comparison is **O(n) rule traversal versus expected
O(1) lookup**: scanning a rule list takes more work as the list grows, while a hash
lookup finds the result without checking each entry in sequence. At 250 entries,
that replaces up to 250 rule checks with one lookup.

The map also keeps common matching logic in one place and provides separate entry
statistics without 250 consuming rules. Adding customers grows the map's contents
instead of making the sequential rule list longer.

Ordinary rules remain useful when entries need different logging, rate limits or
other statements, when intentional first-match ordering matters, or when a handful
of simple rules is already clear. Entry numbers do **not** establish map priority.

## Read the syntax

- `map ipv4 NAME` or `map ipv6 NAME` creates the family-specific object.
  `map inet NAME` uses family-neutral keys and verdict results for both families.
- `match` lists the packet fields that form the lookup key. Multiple fields are
  combined: every field must match the same entry. This is called a concatenation.
- `result-type` says what each entry returns: `verdict`, `address`, `port`, or
  `address-port`.
- `entry NAME` supplies one value/range for every selected field and its result.
  Entry names can be words or numbers; they identify entries for management.
- `default-result` optionally supplies a result when no entry matches.
- A consuming firewall or NAT rule uses `map NAME`.

A map definition alone does not process traffic. It must be referenced by a rule.
Entries are unordered and overlapping complete keys are rejected. This is not
longest-prefix routing: a broad prefix and a more-specific exception cannot overlap
in every other field of the same map. Use an earlier ordinary rule for an exception,
or split the ranges into non-overlapping entries.

Without `default-result`, a lookup miss skips the rest of the consuming rule and
continues with the next rule. **A miss is not an implicit drop.** The chain's later rules and default action
still matter. Statements executed before the lookup, such as a rule counter or
logging, are not undone by a miss. Entry counters specifically identify map hits.

## Default results

A default result is the native `* : result` catch-all element. Normal entries take
precedence; the fallback is selected only when the complete lookup key misses.
It works with exact keys, ranges, and concatenations. It is not a wildcard for
an individual field, and it needs no `entry` name or match values.

Use the same result fields as an ordinary entry:

```text
set firewall group map inet SERVICES description "Shared service policy with a fallback"
set firewall group map inet SERVICES counter
set firewall group map inet SERVICES last-used

set firewall group map inet SERVICES match protocol destination-port
set firewall group map inet SERVICES result-type verdict

set firewall group map inet SERVICES entry HTTPS protocol tcp destination-port 443 result action accept
set firewall group map inet SERVICES entry DNS protocol udp destination-port 53 result action accept

set firewall group map inet SERVICES default-result action drop

set firewall inet forward filter rule 100 map SERVICES
```

The default drops unmatched **port-bearing traffic** reaching this lookup. A map
with transport-port keys still has its protocol/header guard; it does not turn
into a catch-all for ICMP or bypass the consuming rule's other conditions.

Verdict defaults accept `accept`, `drop`, `continue`, `return`, or `jump`. A jump
also requires a named chain in the same family:

```text
set firewall inet name OTHER_SERVICES default-action drop
set firewall inet name OTHER_SERVICES rule 10 protocol tcp destination-port 22 action accept

set firewall group map inet SERVICES default-result action jump jump-target OTHER_SERVICES
```

Translation defaults must match `result-type`: `address` requires an address,
`port` requires a port, and `address-port` requires both. For example, direct
otherwise-unlisted public ports to a fallback service:

```text
set firewall group map ipv4 PORT_FORWARD description "Public services with a fallback endpoint"

set firewall group map ipv4 PORT_FORWARD match protocol destination-port
set firewall group map ipv4 PORT_FORWARD result-type address-port

set firewall group map ipv4 PORT_FORWARD entry HTTPS protocol tcp destination-port 443 result address 10.0.0.10
set firewall group map ipv4 PORT_FORWARD entry HTTPS result port 8443

set firewall group map ipv4 PORT_FORWARD default-result address 10.0.0.20 port 8080

set nat destination rule 100 inbound-interface eth0 map PORT_FORWARD
```

A map may contain only its default. Removing `default-result` restores ordinary
lookup-miss behavior. Default jumps participate in reference protection, hook
restrictions, and chain rebuilding just like explicit-entry jumps.

Map-level or inherited global `counter` and `last-used` settings apply to the
default element too. `show firewall group map ...` displays it as a `default`
row with `*` in the key columns and its own statistics.

## Using these examples

The numbered examples are independent scenarios, not one configuration to paste
all at once. Enter their `set` commands in configuration mode, then `commit`;
use `save` if they should survive reboot. Inspection commands are operational:
prefix them with `run` while in configuration mode.

Addresses and interfaces are examples. Arrange interface addressing, routing and
return paths separately. These snippets demonstrate classification, not a complete
bidirectional production firewall. A forward permit does not automatically permit
the reverse direction. An earlier established/related state policy can handle
return traffic, but also means those packets bypass later maps and their counters.
Do not change a management hook's default action without retaining your access rule.

## 1. Different actions for different client/service combinations

Allow one client's HTTPS service, allow another client's SSH service, and explicitly
drop a third client's HTTPS traffic. Other combinations reach the forward default.

```text
set firewall group map ipv4 CLIENT_SERVICES description "Per-client service decisions"
set firewall group map ipv4 CLIENT_SERVICES counter
set firewall group map ipv4 CLIENT_SERVICES last-used

set firewall group map ipv4 CLIENT_SERVICES match source-address destination-address protocol destination-port
set firewall group map ipv4 CLIENT_SERVICES result-type verdict

set firewall group map ipv4 CLIENT_SERVICES entry WEB source-address 10.10.1.10 destination-address 10.20.1.20 protocol tcp destination-port 443 result action accept
set firewall group map ipv4 CLIENT_SERVICES entry WEB description "Workstation to web application"
set firewall group map ipv4 CLIENT_SERVICES entry SSH source-address 10.10.1.11 destination-address 10.20.1.20 protocol tcp destination-port 22 result action accept
set firewall group map ipv4 CLIENT_SERVICES entry BLOCKED source-address 10.10.1.12 destination-address 10.20.1.20 protocol tcp destination-port 443 result action drop

set firewall ipv4 forward filter rule 100 map CLIENT_SERVICES
set firewall ipv4 forward filter default-action drop
```

`10.10.1.10 -> 10.20.1.20 TCP/443` is accepted; the same client on TCP/22
misses the map and reaches the default drop. A matching BLOCKED entry drops
immediately. Changing the entry identifier from `WEB` to `1` would not change priority.

```text
show firewall group map ipv4 CLIENT_SERVICES
show firewall ipv4 forward filter rule 100 detail
```

## 2. Select a policy chain by incoming interface

Different departments can enter different policy chains through one dispatch rule.
The named chains supply the detailed policy, so the map need only select a chain.

```text
set firewall ipv4 name STAFF_POLICY default-action drop
set firewall ipv4 name STAFF_POLICY rule 10 protocol tcp destination-port 443 action accept

set firewall ipv4 name GUEST_POLICY default-action drop
set firewall ipv4 name GUEST_POLICY rule 10 protocol udp destination-port 53 action accept

set firewall group map ipv4 DEPARTMENT_POLICY match inbound-interface
set firewall group map ipv4 DEPARTMENT_POLICY result-type verdict

set firewall group map ipv4 DEPARTMENT_POLICY entry STAFF inbound-interface eth1 result action jump
set firewall group map ipv4 DEPARTMENT_POLICY entry STAFF result jump-target STAFF_POLICY
set firewall group map ipv4 DEPARTMENT_POLICY entry GUEST inbound-interface eth2 result action jump
set firewall group map ipv4 DEPARTMENT_POLICY entry GUEST result jump-target GUEST_POLICY

set firewall ipv4 forward filter rule 110 map DEPARTMENT_POLICY
set firewall ipv4 forward filter default-action drop
```

Traffic entering eth1 jumps to STAFF_POLICY; eth2 jumps to GUEST_POLICY. Traffic
on another interface misses and reaches the forward default. The named chains here
have terminal default drops. An explicit `return` inside a called chain instead
returns to the caller. `continue` as a map result simply proceeds to the next rule.
A map cannot return `reject`; use a jump to a chain containing an ordinary reject rule.

```text
show firewall group map ipv4 DEPARTMENT_POLICY
show firewall ipv4 name STAFF_POLICY
show firewall ipv4 name GUEST_POLICY
```

## 3. IPv6 service policy

IPv6 uses the same model, with its own map namespace and addresses.

```text
set firewall group map ipv6 PUBLIC_SERVICES match destination-address protocol destination-port
set firewall group map ipv6 PUBLIC_SERVICES result-type verdict

set firewall group map ipv6 PUBLIC_SERVICES entry HTTPS destination-address 2001:db8:20::10 protocol tcp destination-port 443 result action accept
set firewall group map ipv6 PUBLIC_SERVICES entry DNS destination-address 2001:db8:20::53 protocol udp destination-port 53 result action accept

set firewall ipv6 forward filter rule 120 map PUBLIC_SERVICES
set firewall ipv6 forward filter default-action drop
```

HTTPS to `2001:db8:20::10` matches; TCP/443 to `2001:db8:20::11` does not.
TCP DNS is not covered by the UDP entry; add a separate TCP entry if needed.

```text
show firewall group map ipv6 PUBLIC_SERVICES
show firewall ipv6 forward filter rule 120
```

## 4. Classify applications by source subnet and DSCP

A map can make decisions using fields other than addresses and ports. Here two
non-overlapping source networks are permitted only with a particular DSCP value.
This matches existing markings; it does not set DSCP or provide QoS scheduling.

```text
set firewall group map ipv4 MARKED_APPLICATIONS match source-address dscp
set firewall group map ipv4 MARKED_APPLICATIONS result-type verdict

set firewall group map ipv4 MARKED_APPLICATIONS entry VOICE source-address 10.30.0.0/24 dscp 46 result action accept
set firewall group map ipv4 MARKED_APPLICATIONS entry VIDEO source-address 10.31.0.0/24 dscp 34 result action accept

set firewall ipv4 forward filter rule 130 map MARKED_APPLICATIONS
set firewall ipv4 forward filter default-action drop
```

A packet from `10.30.0.10` with DSCP 46 matches VOICE; DSCP 0 misses. Treat
markings from untrusted endpoints accordingly; the map is not proof of application identity.

```text
show firewall group map ipv4 MARKED_APPLICATIONS
```

## 5. DNAT several public addresses to different servers

An `address` result changes only the address. The explicit TCP/443 match is allowed
on the NAT rule because neither protocol nor port is part of this map's key.

```text
set firewall group map ipv4 PUBLIC_ADDRESSES match destination-address
set firewall group map ipv4 PUBLIC_ADDRESSES result-type address

set firewall group map ipv4 PUBLIC_ADDRESSES entry WEBSITE destination-address 203.0.113.10 result address 10.20.0.10
set firewall group map ipv4 PUBLIC_ADDRESSES entry PORTAL destination-address 203.0.113.11 result address 10.20.0.11

set nat destination rule 200 inbound-interface eth0 protocol tcp destination-port 443 map PUBLIC_ADDRESSES
```

Incoming TCP/443 for `203.0.113.10` becomes `10.20.0.10:443`. Traffic for
`203.0.113.12` misses; this rule performs no translation, and later NAT rules may
still apply. NAT does not permit forwarding: add the required firewall policy for
the translated server address. Public addresses must be reachable on the router.

```text
show firewall group map ipv4 PUBLIC_ADDRESSES
show nat destination rule 200 detail
show nat destination translations
```

## 6. DNAT by public address, protocol and port

Publish different services, including changing the server-side port.

```text
set firewall group map ipv4 PORT_FORWARD counter

set firewall group map ipv4 PORT_FORWARD match destination-address protocol destination-port
set firewall group map ipv4 PORT_FORWARD result-type address-port

set firewall group map ipv4 PORT_FORWARD entry HTTPS destination-address 203.0.113.10 protocol tcp destination-port 443 result address 10.20.0.10 result port 8443
set firewall group map ipv4 PORT_FORWARD entry VPN destination-address 203.0.113.10 protocol udp destination-port 51820 result address 10.20.0.20 result port 51820

set nat destination rule 210 inbound-interface eth0 map PORT_FORWARD
```

TCP/443 becomes `10.20.0.10:8443`; UDP/51820 becomes `10.20.0.20:51820`.
TCP/51820 misses. Do not repeat `protocol` or `destination-port` on rule 210:
those fields already come from the map. Do not add `translation` either—the map
supplies the complete translation result. A hit chooses one configured result;
this is deterministic service selection, not round-robin load balancing.

```text
show firewall group map ipv4 PORT_FORWARD
show nat destination rule 210
show nat destination translations destination-address 203.0.113.10 detail
```

## 7. Translate only the destination port

A `port` result keeps the destination address unchanged. This example assumes
`192.0.2.10` is a routed server reached through the router.

```text
set firewall group map ipv4 SERVICE_PORTS match protocol destination-port
set firewall group map ipv4 SERVICE_PORTS result-type port

set firewall group map ipv4 SERVICE_PORTS entry WEB protocol tcp destination-port 8443 result port 443
set firewall group map ipv4 SERVICE_PORTS entry SSH protocol tcp destination-port 2222 result port 22

set nat destination rule 220 inbound-interface eth0 destination-address 192.0.2.10 map SERVICE_PORTS
```

`192.0.2.10:8443` becomes `192.0.2.10:443`. The same service port aimed at another
address does not pass the rule's explicit address match. Unlisted ports continue
to later NAT rules without translation by this rule.

```text
show firewall group map ipv4 SERVICE_PORTS
show nat destination rule 220 detail
```

## 8. SNAT departments to different public addresses

Use a source-prefix lookup to choose each department's public source address.

```text
set firewall group map ipv4 DEPARTMENT_SNAT match source-address
set firewall group map ipv4 DEPARTMENT_SNAT result-type address

set firewall group map ipv4 DEPARTMENT_SNAT entry STAFF source-address 10.40.0.0/24 result address 203.0.113.20
set firewall group map ipv4 DEPARTMENT_SNAT entry LAB source-address 10.41.0.0/24 result address 203.0.113.21

set nat source rule 230 outbound-interface eth0 map DEPARTMENT_SNAT
```

An outgoing packet from `10.40.0.25` selects `203.0.113.20`; one from
`10.41.0.25` selects `203.0.113.21`. `10.42.0.25` misses and may reach a later
masquerade or other NAT rule. This is many-to-one address selection per subnet,
not preservation of host bits in a one-to-one prefix translation. Return traffic
must be routed back to this router; configuring a map does not advertise public
addresses, assign them to interfaces, or arrange proxy ARP.

```text
show firewall group map ipv4 DEPARTMENT_SNAT
show nat source rule 230
show nat source translations
```

## 9. SNAT telemetry senders to explicit address/port pairs

Some collectors identify senders by a fixed public endpoint. Give two controlled
UDP senders separate translated ports on the same public address.

```text
set firewall group map ipv4 TELEMETRY_SNAT match source-address protocol
set firewall group map ipv4 TELEMETRY_SNAT result-type address-port

set firewall group map ipv4 TELEMETRY_SNAT entry SENSOR_A source-address 10.50.0.10 protocol udp result address 203.0.113.30 result port 20010
set firewall group map ipv4 TELEMETRY_SNAT entry SENSOR_B source-address 10.50.0.11 protocol udp result address 203.0.113.30 result port 20011

set nat source rule 240 outbound-interface eth0 destination-address 198.51.100.50 destination-port 514 map TELEMETRY_SNAT
```

UDP traffic from `10.50.0.10` to collector `198.51.100.50:514` selects
`203.0.113.30:20010`. Another sender misses. TCP fails the map's protocol selection.
Fixed translated endpoints can constrain concurrent connection tuples; they are
not a general replacement for normal source-port allocation under arbitrary load.

```text
show firewall group map ipv4 TELEMETRY_SNAT
show nat source rule 240 detail
show nat source translations destination-address 198.51.100.50 detail
```

## 10. A match-group gates access to a service map

Allow only approved source/interface combinations to reach the map. The group
owns `source-address` and `inbound-interface`; the map owns `destination-address`,
`protocol` and `destination-port`. Their fields do not conflict.

```text
set firewall group match-group ipv4 APPROVED_CLIENTS match source-address inbound-interface

set firewall group match-group ipv4 APPROVED_CLIENTS entry OFFICE source-address 10.60.0.0/24 inbound-interface eth1
set firewall group match-group ipv4 APPROVED_CLIENTS entry SUPPORT source-address 10.61.0.10 inbound-interface eth2

set firewall group map ipv4 APPLICATION_POLICY match destination-address protocol destination-port
set firewall group map ipv4 APPLICATION_POLICY result-type verdict

set firewall group map ipv4 APPLICATION_POLICY entry WEB destination-address 10.70.0.10 protocol tcp destination-port 443 result action accept
set firewall group map ipv4 APPLICATION_POLICY entry LEGACY destination-address 10.70.0.20 protocol tcp destination-port 23 result action drop

set firewall ipv4 forward filter rule 250 match-group APPROVED_CLIENTS map APPLICATION_POLICY
set firewall ipv4 forward filter default-action drop
```

An office client entering eth1 and requesting the web application passes both
lookups. The same source entering eth2 fails the match-group, so the map is not
used. An approved client requesting an unlisted service passes the group but
misses the map and reaches the default drop.

```text
show firewall group match-group ipv4 APPROVED_CLIENTS
show firewall group map ipv4 APPLICATION_POLICY
show firewall ipv4 forward filter rule 250 detail
```

## Limits, counters and common mistakes

- The family in the group path describes its IP addresses, not its allowed hooks.
  [Ingress](firewall.md#ingress-filtering) can reuse packet-field maps, but cannot
  consume connection fields or outgoing-interface keys. VLAN ID/priority keys
  are available for ingress consumers. Verification follows verdict-map jumps
  through nested named chains as well as checking the map itself.
- Each object needs 1–5 key fields and at most 64 bytes of key storage, including
  four-byte alignment per field. Two IPv6 addresses plus two interface names
  already occupy 64 bytes; adding a port exceeds the limit. A long entry name is
  metadata, not a lookup field. The result is separate from the lookup key.
- Every entry must supply exactly the declared fields. Entry fields are scalar:
  setting the same entry's port again replaces it. Create another named entry for
  an alternative, or use a supported contiguous range. No omitted-field wildcards.
- Port keys require `protocol` in the key and a supported port-bearing protocol
  in every entry: TCP, UDP, UDP-Lite, SCTP or DCCP. NAT `port` and `address-port`
  results require a protocol key with TCP or UDP. ICMP type/code and TCP flags also
  require the appropriate protocol key.
- Firewall consumers require `verdict`. NAT consumers require `address`, `port`
  or `address-port`; nVyR currently exposes IPv4 NAT only. The address result is
  a single literal address, not `masquerade`. Mark-setting and other arbitrary
  nftables result types are not supported by this CLI.
- Ordinary matches are allowed for fields absent from the map. Positive fields
  cannot be duplicated across the rule, singleton groups, match-group and map.
  Negative matches are checked separately and can narrow a positive selection.
- DNAT must match an inbound interface, and SNAT an outbound interface, supplied
  by the rule or its group/map. Do not use an outbound-interface key for DNAT:
  prerouting has not selected that interface yet. Other hook restrictions apply
  to every key, including through named-chain jumps.
- Maps do not support dynamic packet-path learning. Use a dynamic match-group
  when packets should create or refresh membership.
- `counter` and `last-used` are map-level settings that give each entry its own
  tracking. They are also inherited from `firewall global-options`. Rule counters
  can count packets reaching a lookup even on misses; inspect entry counters for
  lookup hits. NAT statistics normally cover first packets, not all translated bytes.
- Map descriptions label the object. Entry comments use `entry-name|description`;
  their combined UTF-8 length must fit 128 bytes. TCP flag patterns can expand one
  logical entry into multiple native elements; they need not be one kernel counter.
- Changing a map rebuilds it and affected consumer chains atomically, resetting
  their runtime counters. Unchanged objects survive unrelated commits. Removing a
  referenced object is blocked; remove/update consumers in the same candidate first.
- nftables 1.1.7 has guarded limitations for one-field and five-field maps containing
  conntrack zone/accounting fields. Two-to-four-field forms are allowed for those
  fields. See [upstream issues](../dev/upstream-issues.md) for the affected cases.

For connection-field and TCP-flag syntax shared by both objects, see the examples
in [match-groups](firewall-match-groups.md). For translation lifetimes and rule
inspection, see [NAT](nat.md). Full command paths are in the
[command tree](command-tree.md).
