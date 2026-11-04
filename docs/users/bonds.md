# Bond interfaces

A bond presents several links as one interface. Put addresses, DHCP clients,
VLANs and VRF membership on the bond. Configure each member interface first;
a port can belong to only one bond or bridge. Set the MTU on the bond;
its members inherit that MTU while attached.

## Two links with LACP

Configure the peer for LACP on the same ports. Both ends can be active; if one
is passive, the other must initiate negotiation.

```text
set interfaces ethernet eth2
set interfaces ethernet eth3

set interfaces bond bond0 mode 802.3ad
set interfaces bond bond0 member interface eth2
set interfaces bond bond0 member interface eth3

set interfaces bond bond0 lacp rate fast
set interfaces bond bond0 transmit-hash-policy layer3+4

set interfaces bond bond0 vif 10 address 192.0.2.1/24
```

`lacp min-links` controls how many active links an aggregator needs before
reporting carrier. A transmit hash distributes flows; one TCP connection
normally uses one member.

`show interfaces bond bond0 lacp` shows one row per member. Compare the
aggregator ID and partner MAC across ports, then check the actor (local) and
partner flags. `SCD` means synchronized, collecting and distributing. A dash
means that flag is clear. `Unknown` means the kernel did not report the value.

Use `show interfaces bond bond0 lacp detail` to compare each member's actor
and partner system MACs, priorities, keys, port numbers and all eight state flags.

## Primary and standby

Active-backup uses one port at a time and does not require an LACP peer.
This example waits 200 ms before reusing a recovered link. With reselection
set to `failure`, the backup stays active until it fails.

```text
set interfaces ethernet eth2
set interfaces ethernet eth3

set interfaces bond bond0 mode active-backup
set interfaces bond bond0 member interface eth2
set interfaces bond bond0 member interface eth3
set interfaces bond bond0 primary eth2
set interfaces bond bond0 primary-reselect failure

set interfaces bond bond0 link-monitor mii interval 100ms
set interfaces bond bond0 link-monitor mii up-delay 200ms
```

To use neighbor reachability instead of carrier, replace the MII monitor with
a probe interval and one or more IPv4 ARP or IPv6 Neighbor Solicitation targets.
Use a target reachable on the bonded network.

```text
delete interfaces bond bond0 link-monitor mii

set interfaces bond bond0 link-monitor probe interval 1s
set interfaces bond bond0 link-monitor probe ipv4-target 192.0.2.254
```

## Other modes and operations

Linux also supports round robin, broadcast, static XOR, transmit load balancing
and adaptive load balancing. Mode-specific controls include packets per member
(round robin), flow distribution (XOR, LACP, TLB and ALB) and MAC failover
(active-backup). Changing mode can interrupt traffic. The
[command tree](command-tree.md) lists the settings and their value choices.

```text
show interfaces bond
show interfaces bond bond0
show interfaces bond bond0 member eth2

reset interfaces bond bond0 active-member eth3
```

The reset selects a member at runtime in active-backup, TLB or ALB mode; it
does not change the configured primary.
