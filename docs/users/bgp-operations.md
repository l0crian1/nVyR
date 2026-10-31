# BGP operational commands

For implementation and testing, see the [developer guide](../dev/bgp-operations.md).

BGP commands preserve FRR's keyword and argument order and return its native text.
Use `run` in configuration mode. Existing paging and output pipes apply. This
tree covers IPv4 and IPv6 unicast; other address families remain deferred.

## Displays

```text
show bgp
show bgp summary
show bgp summary failed
show bgp summary established neighbor 192.0.2.2 terse wide
show bgp summary remote-as external
show bgp summary remote-as 65001

show bgp ipv4 unicast
show bgp ipv6 unicast summary
show bgp vrf BLUE ipv4 unicast summary
show bgp vrf all ipv6 unicast

show bgp ipv4 unicast 192.0.2.0/24
show bgp ipv6 unicast 2001:db8::/32 longer-prefixes
show bgp ipv4 unicast 192.0.2.0/24 internal bestpath

show bgp neighbors
show bgp neighbors 192.0.2.2
show bgp ipv6 neighbors 2001:db8::2 graceful-restart

show bgp vrf BLUE ipv4 unicast neighbors 192.0.2.2 routes
show bgp vrf BLUE ipv4 unicast neighbors 192.0.2.2 advertised-routes detail
show bgp ipv4 unicast neighbors 192.0.2.2 received-routes
show bgp ipv4 unicast neighbors 192.0.2.2 filtered-routes
show bgp ipv4 unicast neighbors 192.0.2.2 bestpath-routes
show bgp ipv4 unicast neighbors 192.0.2.2 prefix-counts

show bgp ipv4 unicast route-map IMPORT
show bgp ipv6 unicast prefix-list ALLOWED
show bgp ipv4 unicast access-list ALLOWED
show bgp ipv4 unicast filter-list AS_PATHS
show bgp ipv4 unicast community 65000:10 exact-match
show bgp ipv6 unicast large-community 65000:10:20
show bgp ipv4 unicast community-list COMMUNITIES
show bgp ipv6 unicast large-community-list LARGE exact-match

show bgp ipv4 unicast self-originate
show bgp ipv4 unicast version 10
show bgp ipv6 unicast statistics

show bgp ipv4 unicast dampening flap-statistics
show bgp ipv4 unicast dampening dampened-paths
show bgp ipv4 unicast dampening parameters

show bgp router
show bgp vrfs
show bgp vrfs BLUE
show bgp vrf BLUE bestpath
show bgp peer-group PEERS

show bgp vrf BLUE nexthop 192.0.2.2 detail
show bgp import-check-table detail
```

The generated [command tree](command-tree.md) lists the full combinations.
FRR permits neighbor detail with no AFI or with `ipv4`/`ipv6`, but after an
explicit `unicast` it requires a route/status subcommand. The CLI respects that
distinction instead of rearranging the command. Received routes require FRR's
inbound soft-reconfiguration storage; native errors remain visible.

## Resets and refreshes

Displays require operator access. Resets require net-admin or administrator.
An unsuffixed clear resets the selected sessions; `soft in` and `soft out`
refresh routing information without a hard session reset.

```text
clear bgp 192.0.2.2
clear bgp 2001:db8::2 soft in
clear bgp ipv4 unicast 192.0.2.2 soft out
clear bgp vrf BLUE ipv6 unicast 2001:db8::2 soft in
clear bgp vrf BLUE * soft out
clear bgp 65001 soft
clear bgp external out
clear bgp peer-group PEERS soft in
clear bgp 192.0.2.2 in prefix-filter

clear bgp 192.0.2.2 message-stats
clear bgp 192.0.2.2 capabilities
```

`*` selects all peers in the selected scope. There is no implicit target when
`clear bgp` is entered alone. Completion suggests configured neighbor addresses
and peer groups, with their owning VRFs in the descriptions.
