# Routing-policy operational commands

For implementation and testing, see the [developer guide](../dev/policy-operations.md).

These commands inspect installed FRR policies, preserving native syntax, argument
order and output. They are available to all roles and through `run` in configuration
mode. Names are suggested from the configured policies; the displayed state comes
from FRR rather than the candidate configuration.

## Commands

```text
show route-map
show route-map IMPORT

show ip access-list
show ip access-list ACL4

show ipv6 access-list
show ipv6 access-list ACL6

show ip prefix-list
show ip prefix-list PREFIXES
show ip prefix-list PREFIXES seq 10
show ip prefix-list summary [PREFIXES]
show ip prefix-list detail [PREFIXES]
show ip prefix-list PREFIXES 192.0.2.0/24 [longer|first-match]

show ipv6 prefix-list
show ipv6 prefix-list PREFIXES
show ipv6 prefix-list PREFIXES seq 10
show ipv6 prefix-list summary [PREFIXES]
show ipv6 prefix-list detail [PREFIXES]
show ipv6 prefix-list PREFIXES 2001:db8::/32 [longer|first-match]

show bgp as-path-access-list [AS_PATHS]
show ip as-path-access-list [AS_PATHS]

show bgp community-list
show bgp community-list COMMUNITIES detail

show bgp large-community-list
show bgp large-community-list LARGE_COMMUNITIES detail

clear route-map counters
clear route-map counters IMPORT
```

Brackets indicate optional arguments, not literal characters. Counter resets
require net-admin or administrator access. Without a name, FRR clears all
route-map counters. The full FRR keyword is `counters`; `counter` works as an
ordinary CLI abbreviation. Resetting counters does not delete policies or routes.

## Policy definitions versus matching routes

Community-list definitions require attention to native FRR syntax: the bare
`show bgp community-list` lists definitions, while `show bgp community-list NAME`
shows routes matching that list. Add `detail` to inspect the named definition.
Large-community lists have the same distinction. The existing family- and
VRF-scoped BGP route selectors keep their previous behavior.
