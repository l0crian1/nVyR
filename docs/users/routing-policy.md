# Routing policies

For implementation and testing, see the [developer guide](../dev/routing-policy.md).

Routing policies live under `policy`, independently of any routing protocol or
VRF. Access lists, prefix-lists, and route-maps share one configuration owner.
This implementation creates no BGP instances, neighbors, or address families.

## Access lists

```text
set policy access-list ipv4 INTERNAL description "Internal routing policy"

set policy access-list ipv4 INTERNAL rule 10 action permit prefix 10.0.0.0/8
set policy access-list ipv4 INTERNAL rule 20 action permit prefix 192.168.0.0/16 exact-match
set policy access-list ipv4 INTERNAL rule 30 action permit address 10.0.20.0 wildcard-mask 0.0.255.0
set policy access-list ipv4 INTERNAL rule 100 action deny any

set policy access-list ipv6 INTERNAL rule 10 action permit prefix 2001:db8:100::/48 exact-match
set policy access-list ipv6 INTERNAL rule 100 action deny any
```

An ACL prefix includes more-specific routes unless `exact-match` is present.
IPv4 wildcard bits set to zero compare the corresponding address bits; bits set
to one ignore them. Noncontiguous inverse masks are supported. The example above
matches addresses beginning with `10.0` and ending with `.0`. Ignored address bits
are cleared when rendering to FRR; explicit nVyR configuration retains the entered
address. A zero wildcard matches one address; an all-ones wildcard ignores all bits.

Each rule needs `action permit|deny` and exactly one of `prefix`, `address` with
`wildcard-mask`, or valueless `any`. `exact-match` requires `prefix`. Wildcard
syntax is IPv4-only. These are routing-policy ACLs, not packet-filter rules or
extended source/destination ACLs.

## Prefix-lists

```text
set policy prefix-list ipv4 HOME rule 10 action permit prefix 192.168.0.0/16 ge 24 le 28
set policy prefix-list ipv6 HOME rule 10 action permit prefix 2001:db8:100::/48 le 64
```

Without length modifiers, a prefix-list matches the exact prefix and length.
`ge` and `le` are inclusive. Neither may be shorter than the base prefix, and
`ge` cannot exceed `le`. With only `ge`, the upper limit is the family's maximum
prefix length; with only `le`, the lower limit is the base prefix length.

Both list types evaluate rules in numeric sequence order, with an implicit deny
when no rule matches. Sequences are 1–4294967295, without leading zeroes. IPv4 and
IPv6 lists may share a name. List-level descriptions become native FRR remarks;
rule descriptions remain nVyR metadata because FRR has no per-entry remark field.

## Route-maps

```text
set policy route-map EXPORT rule 10 action permit
set policy route-map EXPORT rule 10 description "Home advertisements"

set policy route-map EXPORT rule 10 match ipv4 prefix-list HOME

set policy route-map EXPORT rule 10 set metric 50
set policy route-map EXPORT rule 10 set local-preference 200
set policy route-map EXPORT rule 10 set weight 100
set policy route-map EXPORT rule 10 set origin igp

set policy route-map EXPORT rule 10 set as-path prepend "65001 65001"

set policy route-map EXPORT rule 10 set community 65001:100
set policy route-map EXPORT rule 10 set community additive

set policy route-map EXPORT rule 10 set large-community 65001:100:200
set policy route-map EXPORT rule 10 set large-community additive

set policy route-map NEXT-HOP rule 10 action permit
set policy route-map NEXT-HOP rule 10 match ipv4 next-hop access-list INTERNAL
set policy route-map NEXT-HOP rule 10 set ipv4 next-hop address 192.0.2.1

set policy route-map NEXT-HOP6 rule 10 action permit
set policy route-map NEXT-HOP6 rule 10 match ipv6 next-hop prefix-list HOME
set policy route-map NEXT-HOP6 rule 10 set ipv6 next-hop global 2001:db8::1

set policy route-map METADATA rule 10 action permit match interface eth1 metric 100 tag 200
```

Route prefix and next-hop matches each accept either family-specific access-list
or prefix-list references. The two list kinds can also be combined as distinct
FRR matching conditions. Referenced lists must exist, and references
prevents deleting a referenced list. Every list and route-map requires at least
one rule. For a deny-all policy, configure an explicit deny rule; empty named
objects cannot be represented by FRR's native CLI.

Route-map sequences are 1–65535, without leading zeroes. `action` is mandatory.
A rule with no matching conditions matches all routes reaching it. Processing
uses FRR's normal permit/deny behavior and implicit final deny. AS-path lists, community lists, and call/continuation controls are supported as described below.
Explicitly entered match/set nodes must contain a setting; an unfinished match
must not accidentally become a permit-all rule.

Standard communities use two 16-bit decimal components. Large communities use
three 32-bit decimal components. Repeated settings collect multiple values;
`additive` retains existing communities and requires at least one configured
community value. AS-path prepending takes one quoted space-separated sequence of
AS numbers and preserves order and duplicates. Origin choices are `igp`, `egp`,
and `incomplete`. Route-map descriptions at the map level are nVyR metadata;
rule descriptions are also represented in FRR.

Policy names, rules, match/set nodes, and their family nodes are anchored. References
offer candidate-aware completion suggestions. See [the command tree](command-tree.md)
for the generated complete syntax.

## BGP attribute policies

AS-path lists use ordered permit/deny rules and FRR POSIX extended regular
expressions, including `_` as an AS boundary. Standard community lists contain
literal values; expanded lists contain regular expressions. Standard and expanded
lists share a name namespace within each community family. List descriptions are
nVyR metadata because FRR does not expose a corresponding native remark.

```text
set policy as-path-list TRANSIT description "Transit AS filter"
set policy as-path-list TRANSIT rule 10 action permit regex "_64501_"

set policy community-list standard CUSTOMER rule 10 action permit community 65000:100
set policy community-list expanded CUSTOMER_REGEX rule 10 action permit regex "^65000:"

set policy large-community-list standard LARGE rule 10 action permit community 65000:100:200
set policy large-community-list expanded LARGE_REGEX rule 10 action permit regex "^65000:100:"

set policy route-map IMPORT rule 10 action permit
set policy route-map IMPORT rule 10 match as-path-list TRANSIT
set policy route-map IMPORT rule 10 match as-path-count 3
set policy route-map IMPORT rule 10 match community-list CUSTOMER exact-match
set policy route-map IMPORT rule 10 match large-community-list LARGE
set policy route-map IMPORT rule 10 match local-preference 200
set policy route-map IMPORT rule 10 match peer 192.0.2.1
set policy route-map IMPORT rule 10 match source-peer PEERS
set policy route-map IMPORT rule 10 match ipv4 next-hop address 192.0.2.1
set policy route-map IMPORT rule 10 match ipv6 next-hop address 2001:db8::1
```

`as-path-count` is a maximum, from 0 through 1028. Each community-family match
accepts one list, with an optional `exact-match`. Standard-community matches also
accept `any` instead of `exact-match`. The normal mode preserves FRR list semantics:
standard list entries match their configured community combination, while expanded
entries apply their regex. `any` selects any-member matching; `exact-match` selects
complete-set matching. Different match conditions remain governed by FRR route-map
semantics. References have candidate-aware completion and deletion protection.

The following setters are alternatives, rather than a single combined example:

```text
set policy route-map EXPORT rule 10 set community no-export
set policy route-map EXPORT rule 10 set community additive
set policy route-map EXPORT rule 10 set community none
set policy route-map EXPORT rule 10 set community-delete CUSTOMER

set policy route-map EXPORT rule 10 set large-community none
set policy route-map EXPORT rule 10 set large-community-delete LARGE

set policy route-map EXPORT rule 10 set as-path prepend "65000 65000"
set policy route-map EXPORT rule 10 set as-path prepend-last-as 3

set policy route-map EXPORT rule 10 set as-path exclude as-number 64501 as-number 64502
set policy route-map EXPORT rule 10 set as-path exclude as-path-list TRANSIT
set policy route-map EXPORT rule 10 set as-path exclude all

set policy route-map EXPORT rule 10 set as-path replace as-number 64501 replacement 65000
set policy route-map EXPORT rule 10 set as-path replace any
set policy route-map EXPORT rule 10 set as-path replace as-path-list TRANSIT replacement 65000

set policy route-map EXPORT rule 10 set ipv4 next-hop address 192.0.2.1
set policy route-map EXPORT rule 10 set ipv4 next-hop peer-address
set policy route-map EXPORT rule 10 set ipv4 next-hop unchanged

set policy route-map EXPORT rule 10 set ipv6 next-hop global 2001:db8::1
set policy route-map EXPORT rule 10 set ipv6 next-hop local fe80::1
set policy route-map EXPORT rule 10 set ipv6 next-hop peer-address
set policy route-map IMPORT rule 10 set ipv6 next-hop prefer-global

set policy route-map IMPORT rule 10 set local-preference +50
set policy route-map IMPORT rule 10 set local-preference -50

set policy route-map EXPORT rule 10 set metric +20
set policy route-map EXPORT rule 10 set metric -20
```

Named standard communities appear in completions with descriptions. `none` clears
an attribute and excludes other values or selective deletion. Without `additive`,
community setters replace existing values. Deletion lists remove permitted values.
AS-path exclusion accepts multiple AS numbers, one list, or `all`. Replacement
accepts one AS number, one list, or `any`; without `replacement`, FRR uses the local
AS. Prepending the last AS accepts 1–10 repetitions. Explicit prepending preserves
order and repeated AS numbers.

IPv6 global and link-local next-hop setters may coexist. Automatic next-hop modes
cannot be combined with explicit addresses. The link-local setter requires a
link-local address; the global setter requires a unicast, non-link-local address.
Invalid address types and malformed POSIX regular expressions are rejected when
entered, including when loading configuration. Local preference and MED accept absolute unsigned values or
signed adjustments with magnitudes through 4294967295.

```text
set policy route-map COMMON rule 10 action permit set local-preference +50

set policy route-map IMPORT rule 10 call COMMON
set policy route-map IMPORT rule 10 on-match next
set policy route-map IMPORT rule 10 on-match goto 100
```

`next` and `goto` are alternatives. Calls and continuation require a permit rule;
called policies returning deny terminate processing. Jumps must move forward and
FRR resumes at the first sequence at or beyond the target. Call cycles are rejected.
