# Carrier-grade NAT

`nat cgnat` assigns each subscriber IPv4 address a public address and a fixed block
of translated ports. TCP and UDP use those ports; ICMP echo uses the same block
for identifiers. Existing connections receive normal conntrack return translation.

## A shared public address pool

```text
set nat cgnat pool INTERNET public-address 203.0.113.10-203.0.113.13
set nat cgnat pool INTERNET port-range 1024-65535 block-size 1024 description "Subscriber Internet access"
set nat cgnat rule 100 source-address 100.64.0.1-100.64.0.200 outbound-interface eth0 pool INTERNET counter
commit
```

This pool has 63 blocks per public address, or 252 subscriber allocations.
Subscribers and public addresses are sorted numerically. In this example,
`100.64.0.1` receives `203.0.113.10:1024-2047`, and `100.64.0.2` receives
`203.0.113.10:2048-3071`. After the 63rd block, allocation continues on the next
public address. An incomplete block at the end of a port range is left unused.
Prefixes include every address, including their network and broadcast addresses.
Overlapping subscriber ranges are combined before allocation.

The default port range is `1024-65535`; the default block size is `1024`.
A block size is a port allocation, not a guaranteed concurrent-connection count.
Native conntrack chooses ports within the block. `port-mapping random` or
`port-mapping fully-random` requests the corresponding native NAT flag.

## More than one subscriber selection

Use `source-address-group` instead of `source-address` for a static IPv4 address
group. Dynamic, imported and GeoIP membership cannot define allocations.

```text
set firewall group address-group ipv4 SUBSCRIBERS address 100.64.1.1-100.64.1.20
set nat cgnat rule 200 source-address-group SUBSCRIBERS outbound-interface eth0 pool INTERNET allocation-offset 200
```

`allocation-offset` counts subscriber blocks from zero. Here it reserves the first
200 blocks for rule 100 and assigns the next 20 to rule 200. Verification rejects
insufficient capacity or public address/port allocations assigned to different
subscribers. Rules may reuse an identical allocation for the same subscriber.

Rule numbers determine evaluation order. Additional matches include inbound and
outbound interfaces and their groups, destinations and address/domain groups,
TCP/UDP/ICMP protocol, transport ports and groups, packet and connection marks,
and IPv4 match-groups. These restrict which connections use the allocation;
they do not change the allocation's subscriber ordering. Omitted protocol permits
TCP, UDP and ICMP. Other IP protocols are not translated by CGN.

Ordinary `nat source` rules run first. A matching ordinary SNAT rule takes
precedence, and a matching `exclude` rule bypasses CGN as well.

```text
set nat source rule 10 source-address 100.64.0.0/16 destination-address 10.0.0.0/8 outbound-interface eth0 exclude
```

## VRFs

Set `vrf` on a CGN rule when its subscriber and external interfaces belong to a
named routing instance. Omission selects the default routing instance.

```text
set nat cgnat pool BLUEPUBLIC public-address 203.0.113.20
set nat cgnat rule 300 vrf BLUE source-address 100.64.2.1-100.64.2.30 outbound-interface eth2 pool BLUEPUBLIC
```

Both sides of this translation stay within BLUE. CGN uses its automatically
assigned conntrack zone and checks egress membership. It does not create routes,
move interfaces, advertise public addresses, or supply proxy ARP. Route the public
pool back to this router using your existing network design. Sharing a default-VRF
uplink with overlapping subscribers in other VRFs is outside this feature.

## Inspect allocations and connections

```text
show nat cgnat
show nat cgnat pool INTERNET
show nat cgnat rules
show nat cgnat rule 100
show nat cgnat subscriber 100.64.0.2
show nat cgnat subscriber 100.64.2.1 vrf BLUE
show nat cgnat public-address 203.0.113.10 port 2500
show nat translations ipv4 source-address 100.64.0.2
```

Subscriber and reverse lookups describe the running configuration's allocation.
Rule counters count NAT evaluations, normally the first packet of a connection.
Use the translation view for actual tracked connections.

Changing a pool, offset, or the sorted subscriber selection can move assignments.
New connections use the new map; commits do not clear existing conntrack entries.
Plan disruptive changes before reusing an old allocation for another subscriber.
Save the configuration when it should survive reboot.

CGN does not add inbound port forwarding, automatic hairpin translation, overflow
blocks, or a full-cone guarantee. Kernel allocation can fail before every port in
a block is occupied, especially with concentrated traffic to one destination.
Size blocks for the workload and use ordinary destination NAT for deliberate
inbound mappings, keeping their ports separate from subscriber allocations.
