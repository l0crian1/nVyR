# Bridge interfaces

For implementation and testing, see the [developer guide](../dev/bridges.md).

Bridges use the shared netlinkd transaction and recovery pipeline. Member
interfaces remain owned by their own configuration scripts; the bridge owns
their attachment and switching settings. Ordinary updates preserve interface
indices and learned MAC/multicast entries. Deleting a bridge detaches its ports.

## Basic configuration

```text
set interfaces bridge br0 description "Users LAN"

set interfaces bridge br0 member interface eth1
set interfaces bridge br0 member interface eth2

set interfaces bridge br0 address 192.0.2.1/24
set interfaces bridge br0 address 2001:db8:1::1/64
set interfaces bridge br0 vrf BLUE
set interfaces bridge br0 link-group 10
```

Members must be configured interfaces, with no addresses, DHCP, direct VRF
assignment, or child VIFs. Put Layer 3 settings on the bridge or bridge VIFs.
An existing Ethernet/veth VIF may itself be a member. A member cannot belong to
multiple bridges, and nested bridges are not supported. Member MTUs must be at
least the bridge MTU. The usual MAC, MTU, description, disable, VRF and link-group
settings apply. `address dhcp` uses the existing DHCPv4 client; DHCPv6 clients
remain deferred.

## VLAN switching

```text
set interfaces bridge br0 vlan-filtering default-pvid 0

set interfaces bridge br0 member interface eth1 vlan 10 pvid untagged
set interfaces bridge br0 member interface eth2 vlan 10
set interfaces bridge br0 member interface eth2 vlan 20

set interfaces bridge br0 vif 10 address 192.0.2.1/24
set interfaces bridge br0 vlan 20 local

set interfaces bridge br0 vlan-statistics vlan-statistics-per-port
```

`vlan <id>` admits tagged traffic. `pvid` classifies untagged ingress into that
VLAN; `untagged` removes the tag on egress. There can be only one PVID per port.
Bridge `vlan <id> local` controls the bridge's own port. Bridge VIFs add their
local VLAN membership automatically.

The default PVID is 1. `default-pvid 0` removes implicit VLAN 1 from the bridge
and its members; explicitly configured VLAN 1 remains. An explicit member PVID
replaces its implicit default. `vlan-protocol 802.1ad` changes the filtering tag
protocol; existing 802.1Q VIFs cannot be combined with that filtering mode.

## Spanning tree and port controls

```text
set interfaces bridge br0 spanning-tree
set interfaces bridge br0 spanning-tree priority 32768 hello-time 2s forward-delay 15s max-age 20s

set interfaces bridge br0 member interface eth1 spanning-tree cost 100 priority 32 bpdu-guard
set interfaces bridge br0 member interface eth2 spanning-tree root-guard

set interfaces bridge br0 member interface eth1 backup-interface eth2
set interfaces bridge br0 member interface eth1 hairpin isolated

set interfaces bridge br0 member interface eth1 flood unknown-unicast disable
set interfaces bridge br0 member interface eth1 learning disable
```

An empty `spanning-tree` node enables Linux STP. Deleting it disables STP;
RSTP/MSTP are not implemented. Native STP port priority is 0–63 (default 32)
and cost is 1–65535 (nVyR default 100). Verification checks timer bounds and relationships. Backup forwarding
redirects a port's egress when carrier is lost; it is not link aggregation.
The backup must be another member of this bridge, without a failover cycle.

Additional port controls include `locked`, unknown multicast/broadcast flood
disable, neighbor suppression, per-VLAN neighbor suppression, and selected
LLDP/EAPOL link-local forwarding. Default-on controls use a `disable` child;
default-off controls are valueless enables.

## MAC and multicast policy

```text
set interfaces bridge br0 mac-learning ageing-time 300s maximum-entries 4096
set interfaces bridge br0 mac-learning link-local disable
set interfaces bridge br0 static-mac 02:00:00:00:00:10 vlan 10 interface eth1

set interfaces bridge br0 multicast querier igmp-version 3 mld-version 2
set interfaces bridge br0 multicast vlan-snooping
set interfaces bridge br0 vlan 10 multicast querier
set interfaces bridge br0 member interface eth1 multicast fast-leave to-unicast
set interfaces bridge br0 multicast static-group VIDEO address 239.1.1.1 interface eth1 vlan 10
```

Without VLAN filtering, static MAC entries use `static-mac <mac> interface
<port>` and multicast entries omit `vlan`. Source-specific multicast entries
also accept `source <address>`. Configured MDB entries must use multicast groups,
same-family unicast sources, and ports admitting the requested VLAN.

Multicast snooping is enabled by default; `multicast snooping disable` turns it
off. Global/per-VLAN query timers and versions, router-port selection, group
limits, and multicast statistics are configurable. Durations accept `s`, `m`,
`h`, or `d`. Omitted multicast options restore native defaults, including the 31.25-second
startup query interval. The generated [command tree](command-tree.md) lists all
options and scalar bounds.

## Operational commands

```text
show interfaces bridge
show interfaces bridge br0
show interfaces bridge br0 member eth1
show interfaces bridge br0 vlan
show interfaces bridge br0 spanning-tree
show interfaces bridge br0 mac
show interfaces bridge br0 multicast

clear interfaces bridge br0 learned-macs
clear interfaces bridge br0 learned-macs interface eth1
clear interfaces bridge br0 learned-macs vlan 10
```

MAC cleanup requires net-admin access and retains static/local entries.
