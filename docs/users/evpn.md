# BGP EVPN over VXLAN

## Stretch a segment

This leaf uses 192.0.2.1 as its VTEP address. Establish underlay reachability to the remote VTEPs and the BGP peer first. Enable the EVPN address family on a neighbor or peer-group. A route reflector can activate its peers and set `route-reflector-client` without configuring a local VXLAN device.

```text
set interfaces bridge br0 vlan-filtering
set interfaces bridge br0 member interface vxlan0 learning disable
set interfaces vxlan vxlan0 source-address 192.0.2.1 destination-port 4789 learning disable
set interfaces vxlan vxlan0 external vlan 10 vni 10010
set protocols bgp local-as 65000 parameters router-id 192.0.2.1
set protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family l2vpn-evpn
set protocols bgp address-family l2vpn-evpn advertise-all-vni
```

Place access ports in VLAN 10. Local access ports learn host MAC addresses. Zebra installs remote MAC entries from Type 2 advertisements and remote flood destinations from Type 3 IMET advertisements. Each leaf can use a different local VLAN number for the same VNI.

FRR derives RDs and RTs automatically. To override them for one segment, give each originating leaf a distinct RD and configure the RTs shared by the participating leaves. Enter each RT separately.

```text
set protocols bgp address-family l2vpn-evpn vni 10010 route-distinguisher 192.0.2.1:10
set protocols bgp address-family l2vpn-evpn vni 10010 route-target both 65000:10
```

## Route between tenant subnets

Use an addressless transit SVI for the L3VNI. Give this SVI a router MAC unique to the leaf. Configure the same gateway IPs and gateway MAC on the tenant-facing SVI of each leaf providing an anycast gateway for VLAN 10.

```text
set vrf name BLUE table 501
set vrf name BLUE vni 50000
set interfaces vxlan vxlan0 external vlan 4000 vni 50000
set interfaces bridge br0 vif 4000 vrf BLUE mac 02:00:00:00:50:01
set interfaces bridge br0 vif 4000 ipv6 no-default-link-local
set interfaces bridge br0 vif 10 vrf BLUE mac 02:00:00:00:10:01
set interfaces bridge br0 vif 10 address 10.10.10.1/24
set interfaces bridge br0 vif 10 address 2001:db8:10::1/64
```

Originate or learn the desired prefixes in BLUE's BGP unicast tables. The following policy exports one IPv4 prefix as a Type 5 and enables IPv6 unicast export. Each VRF can select its own export map per address family.

```text
set policy prefix-list ipv4 BLUE-EXPORT rule 10 action permit prefix 10.20.0.0/24
set policy route-map EXPORT4 rule 10 action permit match ipv4 prefix-list BLUE-EXPORT
set vrf name BLUE protocols bgp local-as 65000
set vrf name BLUE protocols bgp address-family l2vpn-evpn route-target both 65000:50000
set vrf name BLUE protocols bgp address-family l2vpn-evpn advertise ipv4-unicast route-map EXPORT4
set vrf name BLUE protocols bgp address-family l2vpn-evpn advertise ipv6-unicast
```

FRR 10.7.1 documents recursive gateway-IP forwarding for asymmetric routing with traditional bridges. Each PE needs the gateway subnet's L2VNI and a tenant L3VNI. Configure the L3VNI with `set vrf name BLUE vni 50000 prefix-routes-only` on the participating leaves. This keeps the gateway host's Type 2 route on the shared L2 segment. Use `gateway-ip` on the exporting family and `enable-resolve-overlay-index` on the receiving VTEP. The receiver needs a usable Type 2 MAC/IP advertisement for the gateway address.

## Filter and inspect EVPN routes

Peer policy sees EVPN routes. The following map rejects a Type 5 default and permits the remaining advertisements. A Type 5 export map instead evaluates tenant unicast routes before conversion to EVPN.

```text
set policy route-map FABRIC-IN rule 10 action deny match evpn default-route
set policy route-map FABRIC-IN rule 20 action permit
set protocols bgp neighbor 192.0.2.2 address-family l2vpn-evpn route-map import FABRIC-IN
```

Use `match evpn route-type`, `route-distinguisher`, or `vni` to select EVPN attributes. The VNI match examines VXLAN labels on Types 1, 2 and 5. To filter a segment including its Type 3 routes, match its RT with an extended-community list. A MAC access-list selects individual host MACs in Type 2 advertisements.

```text
set policy access-list mac HOSTS rule 10 action permit address 02:00:00:00:10:0a
set policy route-map HOST-POLICY rule 10 action permit match mac access-list HOSTS
show bgp l2vpn evpn summary
show bgp l2vpn evpn route type 2
show bgp l2vpn evpn route type 3
show bgp l2vpn evpn route type 5
show evpn vni
show evpn mac vni 10010
show evpn arp-cache vni 10010
show interfaces vxlan vxlan0 fdb
```

To trace a host move, look up its Type 2 route by MAC and check the selected VTEP against the VXLAN FDB. Supplying an IP selects the MAC/IP advertisement. For routed traffic, use the tenant L3VNI to inspect the remote router MAC and overlay next hop.

```text
show bgp l2vpn evpn route vni 10010
show bgp l2vpn evpn route vni 10010 mac 02:00:00:00:10:0a
show bgp l2vpn evpn route vni 10010 mac 02:00:00:00:10:0a ip 10.10.10.10
show evpn rmac vni 50000
show evpn next-hops vni 50000
```

After correcting a duplicate address, clear the affected MAC or IP. Omitting both clears duplicate state for the entire VNI. A soft BGP refresh reprocesses incoming EVPN routes or readvertises outgoing routes to one peer.

```text
show evpn mac vni 10010 duplicate
show evpn arp-cache vni 10010 duplicate
clear evpn dup-addr vni 10010 mac 02:00:00:00:10:0a
clear evpn dup-addr vni 10010 ip 10.10.10.10
clear bgp l2vpn evpn 192.0.2.2 soft out
```

## Anycast gateway on a MACVLAN

When each leaf needs its own reachable SVI address, give the SVI a leaf-specific
MAC and host address. Put the shared gateway IPs and MAC on a MACVLAN in the
tenant VRF. The following example assumes `br0.10` already carries VLAN 10 in
`BLUE`. Configure the gateway addresses only on the child.

```text
set interfaces macvlan macvlan10 source-interface br0.10 mode private vrf BLUE
set interfaces macvlan macvlan10 mac 02:00:00:00:10:01 address 10.10.10.1/24
set interfaces macvlan macvlan10 address 2001:db8:10::1/64
set interfaces macvlan macvlan10 ipv6 duplicate-address-detection disable
```

Use the same child configuration on each participating leaf. After the bridge
and VLAN are present, install the VLAN-local FDB entry from the Linux shell
on each leaf. This terminates frames for the shared MAC locally.

```sh
sudo bridge fdb replace 02:00:00:00:10:01 dev br0 self local vlan 10
bridge fdb show br br0 vlan 10
```

The native entry lasts for the lifetime of the bridge and VLAN. Reapply it after
reboot or recreation. Look for the gateway MAC on `br0` in VLAN 10 with state
`permanent`. [FRR anycast gateway configuration](https://docs.frrouting.org/en/latest/evpn.html#anycast-gateways-with-single-vxlan-device)
