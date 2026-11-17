# BGP VPNv4 and VPNv6

VPN address families exchange customer routes with an RD and an MPLS label.
The default BGP instance carries those routes between provider routers. Each
customer VRF imports and exports routes through its IPv4/IPv6 unicast family.
Configure MPLS on transport interfaces and provide labeled transport next hops;
see [MPLS](mpls.md) for LDP and static labeled forwarding.

Use loopback peering over a working MPLS transport. The validated nVyR VPNv6 path
uses IPv6 transport next hops. Packaged FRR 10.7.1 has a nexthop-programming defect
for VPNv6 over IPv4 MPLS transport (6VPE): it resolves the mapped BGP next hop to
an IPv4 kernel nexthop, which Linux rejects for an IPv6 route. Linux can forward
this traffic when the nexthop is correctly encoded; this is not an inherent
IPv4 MPLS transport limitation. Native tests confirmed bidirectional forwarding
with manually corrected nexthops, but that correction is not yet implemented in
nVyR. See the [verified upstream issue](../dev/upstream-issues.md#vpnv6-over-ipv4-mpls-transport-incorrect-nexthop-programming).

## Provider peer and customer VRF

```text
set protocols bgp local-as 65000 parameters router-id 192.0.2.1
set protocols bgp neighbor 192.0.2.2 remote-as 65000
set protocols bgp neighbor 192.0.2.2 address-family ipv4-vpn
set protocols bgp neighbor 192.0.2.2 address-family ipv6-vpn

set vrf name BLUE table 100
set vrf name BLUE protocols bgp local-as 65000
set vrf name BLUE protocols bgp address-family ipv4-unicast vpn export import route-distinguisher 65000:100 label auto
set vrf name BLUE protocols bgp address-family ipv4-unicast vpn route-target both 65000:100
set vrf name BLUE protocols bgp address-family ipv4-unicast vpn route-target both 65000:101
set vrf name BLUE protocols bgp address-family ipv6-unicast vpn export import route-distinguisher 65000:100 label auto
set vrf name BLUE protocols bgp address-family ipv6-unicast vpn route-target both 65000:100
```

Assign customer interfaces to BLUE and originate its routes with the usual
unicast `network` or `redistribute` commands. An RD identifies a VPN route; RTs
select which VRFs receive it. Use distinct RDs where separate paths must remain
distinct. Each route-target is an individual multi value, so it can be added or
deleted independently. `both` applies that RT to import and export. Explicit
`import` and `export` RTs may also be configured.

`label auto` uses the system dynamic label allocator. `allocation-mode per-nexthop`
requests labels per next hop; the native default is per VRF. An explicit label
can be configured instead, with per-VRF allocation. `next-hop` overrides the
exported VPN next hop. VPN exchange is also available under default-VRF unicast.

## Import and export maps

RT matching selects candidate imports first. An import route-map can then
filter or modify those routes before they enter the VRF. An export map acts on
routes leaving the VRF and can supply RTs instead of a fixed export RT list.

```text
set policy extended-community-list standard BLUE-RT rule 10 action permit route-target 65000:100
set policy route-map BLUE-IN rule 10 action permit match extended-community-list BLUE-RT
set policy route-map BLUE-IN rule 10 set local-preference 200
set policy route-map BLUE-OUT rule 10 action permit set extended-community route-target 65000:100
set vrf name BLUE protocols bgp address-family ipv4-unicast vpn route-map import BLUE-IN export BLUE-OUT
```

Standard extended-community lists match RTs and site-of-origin values. Expanded
lists use FRR regular expressions. Route maps support exact/any list matching,
extended-community count limits, RT and SoO assignment, clearing extended
communities with `set extended-community none`, and selective removal with
`set extended-community-delete <list>`.

Peer settings are available under neighbor and peer-group VPN families, including
policy filters, AddPath, prefix limits, route reflection and `accept-own`.
`site-of-origin` is available for both VPN peers and unicast customer peers.
FRR retains unmatched VPN RTs by default; configure
`address-family ipv4-vpn disable-retain-route-target-all` (or IPv6) to change that.

## Direct VPN origination

For explicit VPN NLRI, supply both an RD and an advertised label:

```text
set protocols bgp address-family ipv4-vpn network 198.51.100.0/24 route-distinguisher 65000:100 label 16000
set protocols bgp address-family ipv6-vpn network 2001:db8:100::/64 route-distinguisher 65000:100 label 16001
```

An optional route-map applies to each RD/prefix. Advertising a label this way
does not configure the corresponding local MPLS forwarding action. Use VRF
export with `label auto` for normal customer VPNs.

## Operational commands

```text
show bgp ipv4 vpn
show bgp ipv6 vpn summary
show bgp ipv4 vpn rd all
show bgp ipv6 vpn rd 65000:100 2001:db8:100::/64
show bgp ipv4 vpn neighbors 192.0.2.2 advertised-routes
show bgp vrf BLUE ipv4 unicast
show bgp extcommunity-list BLUE-RT detail
show bgp mplsvpn-nh-label-bind detail
show bgp labelpool inuse
show mpls table
clear bgp ipv4 vpn 192.0.2.2 soft out
clear bgp ipv6 vpn 192.0.2.2 soft in
```

Operational words follow the native FRR commands. VPN tables and peer resets use
`ipv4 vpn` / `ipv6 vpn`; configuration uses `ipv4-vpn` / `ipv6-vpn`.
