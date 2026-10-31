# Static routing displays

For implementation and testing, see the [developer guide](../dev/static-routing-operations.md).

For route configuration and validation, see [static routing](static.md).

Operational route commands use FRR's native text output. Existing nVyR paging,
pipe modifiers and operator permissions apply. In configuration mode, prefix
these commands with `run`.

```text
show ip route
show ipv6 route
show ip route static
show ipv6 route static

show ip route 192.0.2.1
show ipv6 route 2001:db8::1
show ip route 192.0.2.0/24
show ipv6 route 2001:db8::/32 longer-prefixes static

show ip route static failed
show ipv6 route static failed
show ip route failed
show ipv6 route failed

show ip route summary
show ipv6 route summary
show ip route summary prefix
show ipv6 route summary prefix
show ip route summary table 254
show ipv6 route summary table 254 prefix

show ip route vrf BLUE
show ip route vrf BLUE 192.0.2.0/24
show ipv6 route vrf BLUE 2001:db8::/32
show ipv6 route vrf BLUE static
show ip route vrf all summary

show ip route table 254 static
show ipv6 route table all

show static routes
show static routes vrf default
show static routes vrf BLUE
```

`show ip route` and `show ipv6 route` display Zebra's routing table. Their
`static` filter selects static routes known to Zebra. `show static routes`
instead displays staticd's configured routes and next-hop status, including
information useful when a route is not installed.

Use `bgp`, `connected`, `kernel` or `local` to select another route origin, or
`tag <1-4294967295>` to select a route tag. These selectors are available for both
families, including after `vrf NAME` and `table NUMBER`, preserving FRR's order:

```text
show ip route bgp
show ipv6 route connected
show ip route kernel
show ipv6 route local

show ip route tag 195
show ipv6 route vrf BLUE tag 195
show ip route table 254 connected
```

The command tree documents the available combinations. `summary` and its
`prefix`/`table` options are also available after `vrf NAME`.
