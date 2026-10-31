# Firewall operational views

For implementation and testing, see the [developer guide](../dev/nftables-operational-data.md).

## CLI display

`show firewall` displays installed firewall chains, sets, maps, and flowtables.
The same display is available from configuration mode through `run show firewall`.
Scope the output without retrieving a different kind of nftables listing:

```text
show firewall ipv4
show firewall ipv6 forward filter

show firewall ipv4 ingress filter
show firewall ipv6 ingress filter rule 10 detail

show firewall ipv4 prerouting raw
show firewall ipv6 prerouting raw
show firewall ipv4 output raw
show firewall ipv6 output raw rule 10 detail

show firewall ipv4 forward filter rule 10
show firewall ipv4 forward filter detail
show firewall ipv4 forward filter rule 10 detail

show firewall state-policy
show firewall state-policy output
show firewall state-policy output detail

show firewall ipv4 name
show firewall ipv4 name SERVICES
show firewall ipv4 name SERVICES rule 20

show firewall group
show firewall group map ipv4 POLICY
show firewall group map ipv4 POLICY detail
show firewall group match-group ipv6 CLIENTS

show firewall group address-group ipv4 LAN
show firewall group icmp-group ipv4 ERRORS
show firewall group icmp-group ipv6 ERRORS detail
show firewall group interface-group WAN
show firewall group mac-group DEVICES
show firewall group port-group WEB

show firewall group limit-group ipv4 LOGIN
show firewall group counter-group DROPS

show firewall flowtable FAST
```

Omit the object name to list that group type or all flowtables. Every scope uses
ordinary tables by default. Rule summaries retain kernel evaluation order and
show the action, counters, last use, and description. `rule` requires a number;
selecting one keeps that rule and the chain's installed default-action row in the
table. It does not switch display formats or invent a default rule when none exists.

Append `detail` at any display scope for headerless label/value tables. This works
for the entire firewall, a family, hook, chain, individual rule, group, or flowtable.
Chain detail shows matches and settings for every selected rule, including its
default-action row. Group detail shows each entry separately. Group metadata does
not repeat counter/last-used enabled flags; the per-entry statistics remain visible.
`Never` means last-used tracking is enabled but no match has
been recorded; `—` means a value is unavailable or tracking is not enabled.

Map and match-group columns follow the renderer's match-field order. Maps add a
result column; enabled counters, last-use tracking, and dynamic expiry appear per
element. Running configuration supplies column names, while entries and statistics
come from the kernel. An unnamed learned element uses `—` for its entry identifier.
If a group's configuration is unavailable, columns show key positions and native
datatypes rather than guessing source/destination semantics. Unsupported expressions
or elements produce a visible warning that the display is incomplete.

ICMP groups show an ICMP type column and, for `match type-code`, an ICMP code
column. Code intervals remain paired with their type. Rule detail identifies the
referenced `icmp-group`, including negative references.

### Rule limits and quotas

Use plural selectors on a chain and singular selectors on one rule:

```text
show firewall ipv4 input filter limits
show firewall ipv4 input filter rule 10 limit

show firewall ipv6 output filter quotas
show firewall ipv6 output filter rule 10 quota

show firewall ipv4 name SERVICES limits
show firewall ipv4 name SERVICES rule 10 limit

show firewall ipv6 name SERVICES quotas
show firewall ipv6 name SERVICES rule 10 quota
```

These selectors also work on the other supported filter/raw chains. Limits show
rate/burst or connection thresholds, active key counts and set capacity. Key
columns follow the installed lookup expression, including concatenations and
address-prefix masks. Rate keys show their remaining expiry in seconds; connection
keys have no expiry column unless the native set supplies a timeout. An entry's
presence does not mean traffic is blocked or currently over its allowance, and
expiry is not the bucket's refill time. Connection entries do not expose a live
connection count, and rate entries do not expose remaining tokens.

Quotas show mode, allowance, used bytes and remaining allowance with binary units.
Used may exceed the allowance; remaining stops at zero. A named limit or quota
is labelled as shared: its state belongs to all referencing rules, not just the
selected rule. Rule selectors omit the unrelated default-action row.

Both views read installed state without resetting anything. They use ordinary
tables; the existing rule/group `detail` views remain available separately.
Unsupported expressions are identified as incomplete information. Missing referenced
objects produce errors rather than invented zero counters.

`| strip-private` masks addresses, MAC addresses, and descriptions before table
formatting. Paging and the ordinary text pipe modifiers use the existing CLI
pipeline. This is read-only and available to all three roles; it does not open a
configuration session or change firewall objects. NAT chains are excluded, though
shared groups used by NAT remain visible under `show firewall group`.

Named counters expose their shared packet/byte totals under `counter-group`.
Named limits expose their rate and burst; per-key limit groups list their active
keys and expirations. For per-key groups, `Configured limit` comes from running
configuration because the kernel set definition does not contain the updating
rule's rate. Remaining bucket tokens are not exposed by nftables. Rule detail
identifies the referenced groups without attributing shared totals to each rule.

## Family-neutral inet views

`show firewall inet` and its hook, named-chain, rule, limit, and quota selectors
use the same table/detail formats as IPv4 and IPv6. Numbered inet rules are read
from the native base chain, while global state policies remain in the separate
state-policy view. Inet hook rules have no default-action row because unmatched
traffic proceeds to family dispatch.

Ingress detail distinguishes the hook's `Ingress interface` attachment from an
explicit `Inbound interface` rule match. Both predicates must match the packet.

```text
show firewall inet forward filter
show firewall inet forward filter rule 10 detail
show firewall inet forward filter limits
show firewall inet forward filter rule 10 limit

show firewall group map inet SERVICES
show firewall group match-group inet LOCAL_SERVICE
show firewall group limit-group inet SHARED

clear firewall group match-group inet LEARNED member inbound-interface eth1
clear firewall group match-group inet LEARNED learned
```
