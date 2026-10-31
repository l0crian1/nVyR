# Match-groups: match combinations, not independent lists

A match-group answers: **"Does this packet match one of these combinations?"**
All fields within an entry must match together. Any entry can satisfy the group.
The consuming firewall rule supplies the action; a [map](firewall-maps.md) instead
stores a result in each entry.

For example, Alice may reach the database and Bob may reach the web server. A
match-group preserves those two relationships. An address-group of Alice and Bob
combined with an address-group of both servers would allow all four pairings.
That difference is why a multi-field group is useful even with only two entries.

## Why use a group instead of 250 individual rules?

If 250 client/service combinations all have the same action, one match-group and
one consuming rule can express them. A packet near the end of a 250-rule chain
may pass hundreds of earlier checks. A group lookup extracts its key and searches
an indexed kernel object, rather than adding one sequential rule evaluation per
configured combination. Adding a client updates the data while the rule's action,
logging and other common settings remain in one place.

For exact-key hash lookups, this is **O(n) rule traversal versus expected O(1)
lookup**. Instead of checking up to 250 rules to find a permitted combination,
one lookup tests membership. The group can grow without adding another sequential
rule check for every new combination.

It also makes policy easier to maintain: change the consuming rule's action or
logging once, and it applies to every matching entry. Entry counters still let
you see which combinations are being used.

Use an address-group, port-group, interface-group or mac-group when membership of
one field is enough. Use a match-group when the relationship between fields
matters. Use a map when those relationships need different results. Keep ordinary
rules when order or per-rule behavior is the point.

## How the fields fit together

- `match source-address destination-address protocol destination-port` declares
  four fields. `match` is anchored, so selectors can be entered on one line.
- Each `entry` supplies all four fields. Entry identifiers can be names or numbers;
  they have no first-match order or routing-style longest-prefix priority.
- `match-group NAME` in a rule tests membership. A hit allows evaluation of the
  rest of that rule; a miss continues to the next rule.
- Entries have no `result` or `action`. The action belongs to the consuming rule,
  or to a separate map used on that rule.

An empty static group is valid but matches no packets. A group by itself does not
allow, block or learn anything. Additional conditions on the rule must also match.
Within a positive match, a field must come from one source: the explicit rule,
a singleton group, the match-group, or a map. Negative matches have their own
conflict checks and may exclude combinations from a positive selection.

## Using these examples

Each numbered scenario is independent. Enter its configuration in configuration
mode, then `commit`; `save` is optional persistence across reboot. Inspection and
clear commands are operational; prefix them with `run` from configuration mode.
Interfaces and addresses are examples, and addressing/routing must already work.

These are matching examples, not complete bidirectional production policies. A
forward allow does not itself allow replies. An earlier established/related state
policy can handle replies, but those packets will bypass later group lookups.
Do not apply an input default drop over an active management session without
retaining a rule for that session.

## 1. Preserve client-to-service permissions

Alice may use HTTPS on the application server. Bob may use SSH on the management
server. Neither permission should accidentally grant the other service.

```text
set firewall group match-group ipv4 CLIENT_ACCESS description "Explicit client-to-service permissions"
set firewall group match-group ipv4 CLIENT_ACCESS counter
set firewall group match-group ipv4 CLIENT_ACCESS last-used

set firewall group match-group ipv4 CLIENT_ACCESS match source-address destination-address protocol destination-port

set firewall group match-group ipv4 CLIENT_ACCESS entry ALICE source-address 10.10.0.10 destination-address 10.20.0.10 protocol tcp destination-port 443
set firewall group match-group ipv4 CLIENT_ACCESS entry ALICE description "Alice to application"
set firewall group match-group ipv4 CLIENT_ACCESS entry BOB source-address 10.10.0.11 destination-address 10.20.0.20 protocol tcp destination-port 22

set firewall ipv4 forward filter rule 100 match-group CLIENT_ACCESS action accept
set firewall ipv4 forward filter default-action drop
```

Alice's HTTPS request matches ALICE. Alice attempting SSH to Bob's management
server matches neither entry and reaches the default drop. Separate source,
destination and port lists would not preserve these pairings.

```text
show firewall group match-group ipv4 CLIENT_ACCESS
show firewall ipv4 forward filter rule 100 detail
```

## 2. Subnets and service ranges

Permit a build subnet to contact build agents on a range of ports, and a monitoring
subnet to query a different set of servers. Each entry is a whole combination.

```text
set firewall group match-group ipv4 SERVICE_RANGES match source-address destination-address protocol destination-port

set firewall group match-group ipv4 SERVICE_RANGES entry BUILD source-address 10.30.0.0/24 destination-address 10.40.0.10-10.40.0.20 protocol tcp destination-port 8000-8010
set firewall group match-group ipv4 SERVICE_RANGES entry MONITOR source-address 10.31.0.0/24 destination-address 10.41.0.0/24 protocol udp destination-port 161

set firewall ipv4 forward filter rule 110 match-group SERVICE_RANGES action accept
set firewall ipv4 forward filter default-action drop
```

`10.30.0.25 -> 10.40.0.15 TCP/8005` matches BUILD. TCP/8011 does not. A build
client cannot use the MONITOR permission because its source subnet differs.
Ranges are inclusive. Non-contiguous alternatives need separate entries.

```text
show firewall group match-group ipv4 SERVICE_RANGES
```

## 3. Bind permitted source addresses to incoming interfaces

Allow only specific source/interface pairs on eth1. This is a source-address
policy, not authentication: a host on that same link could still spoof an allowed IP.

```text
set firewall group match-group ipv4 SOURCE_BINDINGS match inbound-interface source-address

set firewall group match-group ipv4 SOURCE_BINDINGS entry PRINTER inbound-interface eth1 source-address 10.50.0.10
set firewall group match-group ipv4 SOURCE_BINDINGS entry CAMERA inbound-interface eth1 source-address 10.50.0.20

set firewall ipv4 forward filter rule 120 inbound-interface eth1 match-group not SOURCE_BINDINGS action drop
set firewall ipv4 forward filter default-action accept
```

Traffic entering eth1 from `10.50.0.99` is not a member and is dropped. Traffic
from `.10` fails the **negative** group test and continues to the default accept.
The explicit eth1 condition keeps this example from dropping every other interface.
It is valid alongside the negated group even though that group includes an interface
field: the two matches have different polarities.

```text
show firewall group match-group ipv4 SOURCE_BINDINGS
show firewall ipv4 forward filter rule 120 detail
```

## 4. An IPv6 service allowlist

```text
set firewall group match-group ipv6 V6_ACCESS match source-address destination-address protocol destination-port

set firewall group match-group ipv6 V6_ACCESS entry WEB source-address 2001:db8:10::/64 destination-address 2001:db8:20::10 protocol tcp destination-port 443
set firewall group match-group ipv6 V6_ACCESS entry DNS source-address 2001:db8:10::/64 destination-address 2001:db8:20::53 protocol udp destination-port 53

set firewall ipv6 forward filter rule 130 match-group V6_ACCESS action accept
set firewall ipv6 forward filter default-action drop
```

A source in `2001:db8:10::/64` can use the listed HTTPS or UDP DNS endpoint. A
source in another prefix misses. The same group name could independently exist
under IPv4, but an IPv6 rule cannot reference the IPv4 object.

```text
show firewall group match-group ipv6 V6_ACCESS
show firewall ipv6 forward filter rule 130
```

## 5. Select ICMP messages by type and code

Use names for types and numeric values for codes. When combining ICMP with other
fields, a match-group keeps each type paired with its intended code.

```text
set firewall group match-group ipv4 ICMP_MESSAGES match protocol icmp-type icmp-code

set firewall group match-group ipv4 ICMP_MESSAGES entry ECHO protocol icmp icmp-type echo-request icmp-code 0
set firewall group match-group ipv4 ICMP_MESSAGES entry PATH_MTU protocol icmp icmp-type destination-unreachable icmp-code 4

set firewall ipv4 input filter rule 140 match-group ICMP_MESSAGES action accept
set firewall ipv4 input filter default-action drop
```

Echo requests with code 0 and fragmentation-needed messages with code 4 match.
Other destination-unreachable codes miss; configuring a type does not implicitly
permit all its codes. A dedicated ICMP group may be simpler if type/code is all
that is needed. This example deliberately shows the generic group form, which can
also include an address or interface field.

```text
show firewall group match-group ipv4 ICMP_MESSAGES
show firewall ipv4 input filter rule 140
```

## 6. Initial TCP SYN requests for selected services

Match the presence of SYN and absence of ACK, FIN and RST, while allowing other
unmentioned TCP flags. The `and not` syntax keeps normal CLI completion available.

```text
set firewall group match-group ipv4 INITIAL_CONNECTIONS match protocol tcp-flags destination-port

set firewall group match-group ipv4 INITIAL_CONNECTIONS entry HTTPS protocol tcp tcp-flags syn and not ack and not fin and not rst destination-port 443
set firewall group match-group ipv4 INITIAL_CONNECTIONS entry SSH protocol tcp tcp-flags syn and not ack and not fin and not rst destination-port 22

set firewall ipv4 input filter rule 150 match-group INITIAL_CONNECTIONS action accept
set firewall ipv4 input filter default-action drop
```

An initial SYN to TCP/443 matches; SYN+ACK and SYN to TCP/25 do not. This only
permits the opening packets. A usable connection also needs the subsequent
established packets permitted elsewhere. Unspecified flags are not required to be
zero, so this is not an equality test against the entire flag byte.

```text
show firewall group match-group ipv4 INITIAL_CONNECTIONS
show firewall ipv4 input filter rule 150 detail
```

## 7. Match the public service originally contacted before DNAT

A forward rule normally sees the translated destination. Connection fields retain
the original destination, allowing policy based on the public service that the
client contacted. This is independent of the current packet destination.

```text
set nat destination rule 300 inbound-interface eth0 destination-address 203.0.113.10 protocol tcp destination-port 443 translation address 10.20.0.10 translation port 8443

set firewall group match-group ipv4 ORIGINAL_SERVICES match connection protocol original destination-address destination-port

set firewall group match-group ipv4 ORIGINAL_SERVICES entry HTTPS connection protocol tcp original destination-address 203.0.113.10 destination-port 443

set firewall ipv4 forward filter rule 160 connection direction original match-group ORIGINAL_SERVICES action accept
set firewall ipv4 forward filter default-action drop
```

After translation to `10.20.0.10:8443`, the tracked original endpoint still matches
`203.0.113.10:443`. A direct connection to the private server's port 8443 does not
match this group. `connection direction original` restricts the rule to the
initiating direction; the original tuple is also available on reply packets, so
without that condition the same lookup can match replies as well.

```text
show firewall group match-group ipv4 ORIGINAL_SERVICES
show firewall ipv4 forward filter rule 160 detail
show nat destination translations
show conntrack ipv4 destination-address 203.0.113.10 detail
```

Conntrack fields are unavailable for untracked traffic and are not suitable for
raw rules before connection tracking. The packet protocol and stored connection
protocol are separate fields, with separate validation requirements.

## 8. Allow NAT only for approved client/collector combinations

A NAT rule can use a match-group as a condition and supply its own translation.
Here only approved telemetry senders are masqueraded toward a collector.

```text
set firewall group match-group ipv4 NAT_CLIENTS match source-address destination-address protocol destination-port

set firewall group match-group ipv4 NAT_CLIENTS entry SENSOR_A source-address 10.70.0.10 destination-address 198.51.100.50 protocol udp destination-port 514
set firewall group match-group ipv4 NAT_CLIENTS entry SENSOR_B source-address 10.70.0.11 destination-address 198.51.100.50 protocol udp destination-port 514

set nat source rule 310 outbound-interface eth0 match-group NAT_CLIENTS translation address masquerade
```

Sensor A's UDP/514 traffic to that collector is translated. Another client or
service misses and continues to later NAT rules. **Not being translated does not
mean being dropped.** Add firewall policy if unapproved traffic must be blocked,
and check that a later catch-all NAT rule does not intentionally translate it.

```text
show firewall group match-group ipv4 NAT_CLIENTS
show nat source rule 310 detail
show nat source translations
```

The same gating pattern can precede a NAT map when their key fields are disjoint.
For example, a source/interface match-group can gate a destination/protocol/port
map. See [using a match-group with a map](firewall-maps.md#10-a-match-group-gates-access-to-a-service-map)
for a complete combined firewall example.

## 9. Learn and refresh permitted DNS combinations at runtime

A dynamic group starts empty. Matching packets create exact entries from the
selected fields; subsequent matching packets refresh their timeout. No configured
`entry` nodes are allowed on a dynamic group.

This example records DNS requests from a trusted client subnet to one resolver,
then permits combinations in the learned group. The first packet can be learned
by rule 170 and match rule 180 in the same traversal.

```text
set firewall group match-group ipv4 RECENT_DNS counter
set firewall group match-group ipv4 RECENT_DNS last-used

set firewall group match-group ipv4 RECENT_DNS match source-address destination-address protocol destination-port

set firewall group match-group ipv4 RECENT_DNS dynamic timeout 10m size 4096 gc-interval 30s

set firewall ipv4 forward filter rule 170 source-address 10.80.0.0/24 destination-address 192.0.2.53 protocol udp destination-port 53 action continue
set firewall ipv4 forward filter rule 170 add-to-group match-group RECENT_DNS timeout 5m

set firewall ipv4 forward filter rule 180 match-group RECENT_DNS action accept
set firewall ipv4 forward filter default-action drop
```

UDP DNS from `10.80.0.10` to `192.0.2.53` learns that exact four-field key with a
five-minute lifetime, overriding the group's ten-minute default. Another source
outside the trusted subnet is not learned and misses the consuming rule. A group
membership lookup alone does not refresh expiry; the `add-to-group` update does.
This is not connection tracking and does not automatically reverse source/destination
fields for reply packets. It also is not authentication: only learn authorization
state from traffic your policy actually trusts.

```text
show firewall group match-group ipv4 RECENT_DNS
show firewall ipv4 forward filter rule 170 detail

clear firewall group match-group ipv4 RECENT_DNS member source-address 10.80.0.10 destination-address 192.0.2.53 protocol udp destination-port 53
clear firewall group match-group ipv4 RECENT_DNS learned
```

The first clear removes one complete key; the second removes all learned members.
Neither deletes the group configuration. New matching traffic can immediately
repopulate it. A member that has expired no longer matches even if garbage
collection has not yet reclaimed its storage. With the group full, a failed new
insertion skips the rest of the update rule; keep mandatory verdicts separate.
Packet-path learning is supported in firewall rules, not NAT rules or maps.

## 10. Exclude selected combinations from a broader allow

A negated group means **"none of these complete combinations"**, not "every field
is individually different." This lets one broad permit contain precise exceptions.

```text
set firewall group match-group ipv4 WEB_EXCEPTIONS match source-address destination-address protocol destination-port

set firewall group match-group ipv4 WEB_EXCEPTIONS entry RESTRICTED_CLIENT source-address 10.90.0.10 destination-address 192.0.2.80 protocol tcp destination-port 443
set firewall group match-group ipv4 WEB_EXCEPTIONS entry RESTRICTED_SITE source-address 10.90.0.20 destination-address 192.0.2.81 protocol tcp destination-port 443

set firewall ipv4 forward filter rule 190 source-address 10.90.0.0/24 protocol tcp destination-port 443 match-group not WEB_EXCEPTIONS action accept
set firewall ipv4 forward filter default-action drop
```

`10.90.0.10 -> 192.0.2.80 TCP/443` is excluded from the permit and reaches the
default drop. That client going to `192.0.2.81` is not one of the complete exception
keys, so it is accepted. The source and destination values are not independent
blacklists. Because the successful negative lookup finds no element, it cannot
increment an element counter; use a counter on the consuming rule to count those
permitted packets.

```text
show firewall group match-group ipv4 WEB_EXCEPTIONS
show firewall ipv4 forward filter rule 190 detail
```

## Editing, observation and lifecycle

For a static group, add another entry to add an alternative. Reusing the same entry
name edits that entry. Removing `entry NAME` removes only that combination. Remove
a consuming rule/reference before deleting the whole group; dependency checks
protect active references. Changes can be made together in one candidate commit.

Group-level `counter` and `last-used` give entries their own observations. They
are also inherited from the corresponding `firewall global-options` flags. An
entry counter says the group lookup matched; it does not prove a later map or
verdict accepted the packet. The consuming rule's counter placement also matters.
Group descriptions label the object, while entry descriptions label individual
combinations. Entry comments use `entry-name|description` and must fit 128 UTF-8
bytes in total. A TCP flag pattern may expand into several native elements rather
than one kernel counter.

Unchanged groups are preserved across unrelated commits. Changing a group's
definition rebuilds it and affected consumer chains, resetting their counters and
learned state. Boot/recovery rebuilds runtime state from authoritative configuration;
learned entries are not saved policy. Dynamic groups are not a persistent database.

Dynamic defaults, when only `dynamic` is configured, are timeout 10m, size 65536,
and gc-interval 30s. Durations accept positive whole numbers with `s`, `m`, `h` or
`d`. The defaults are effective values, not extra commands written into your saved
configuration. See [dynamic group details](firewall.md#dynamic-address-and-match-groups)
for maximum values and update behavior.

## Validation and common mistakes

- A group's fields must be available at every consuming hook, including through
  named chains. [Ingress](firewall.md#ingress-filtering) accepts packet-field
  groups but rejects connection and outgoing-interface keys. Its VLAN ID/priority
  keys support configured membership; dynamic learning of VLAN keys is not exposed.
- Each group has 1–5 key fields and a 64-byte maximum key size, including four-byte
  alignment for each field. Two IPv6 addresses and two interface names consume
  64 bytes before adding a port. Verification reports field sizes on overflow.
- Every entry supplies exactly the selected fields. Omitting a field is not a
  wildcard. A scalar field cannot hold a list of unrelated values; use another
  entry. Supported prefixes/ranges cover contiguous alternatives.
- Duplicate or overlapping complete keys are rejected. Two entries may share one
  field if another field keeps the complete combinations disjoint. No entry order
  can make an ambiguous overlap safe.
- Port fields need `protocol` in the group key with TCP, UDP, UDP-Lite, SCTP or
  DCCP in each entry. TCP flags require TCP; ICMP type/code require `icmp` or
  `ipv6-icmp` for the family. A consuming rule cannot replace these key requirements.
- Conntrack accounting fields require explicit global connection accounting.
  Rules using connection fields must run after connection tracking. Current
  temporary zone/accounting map restrictions are map-specific; do not assume all
  match-group key forms have the same restriction. See [upstream issues](../dev/upstream-issues.md).
- Hook availability follows the extracted field: OUTPUT has no inbound interface;
  INPUT and prerouting cannot use a not-yet-selected outbound interface. This
  applies through named-chain callers too. VRF-aware INPUT interface matching
  follows the normal firewall interface behavior; a group does not bypass it.
- Dynamic groups accept only supported exact packet extractions. There is no
  configured prefix/range membership alongside dynamic learning, and `entry`
  plus `dynamic` is rejected. A learned `/24` allowance needs a different feature;
  learning an address records the packet's exact address.
- Negating a protocol-specific group does not turn absent protocol headers into
  matches. A TCP group still has a TCP extraction guard; a negated TCP flags group
  is not a way to select every non-TCP packet.

For all available connection fields and general rule options, see
[firewall configuration](firewall.md) and the [command tree](command-tree.md).
For entry-selected actions and translations, continue with [maps](firewall-maps.md).
