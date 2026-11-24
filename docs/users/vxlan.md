# VXLAN interfaces

A fixed-VNI tunnel carries one Ethernet segment between VTEPs. This example uses an IPv4 underlay and the IANA VXLAN UDP port. Configure the other VTEP with the same VNI and destination port and reverse the endpoint addresses.

```text
set interfaces vxlan vxlan10 vni 1010
set interfaces vxlan vxlan10 source-address 192.0.2.1 remote 192.0.2.2
set interfaces vxlan vxlan10 destination-port 4789
set interfaces bridge br10 member interface vxlan10
```

The endpoint addresses can also be IPv6. Configure `source-interface` to select an underlay device, or let routing select the path. The tunnel's `vrf` setting selects its overlay routing domain. A tunnel can carry IP addresses directly. When the tunnel is a bridge port, put the overlay addresses on the bridge or its VIFs. The kernel selects the tunnel MTU when it creates the device unless you specify one. Account for the outer IP, UDP and VXLAN headers in the underlay MTU.

Linux uses its native UDP destination port when the setting is omitted (normally 8472). Set 4789 explicitly for interoperability with devices that use it. For multicast flooding configure `multicast-group` and `source-interface`. For head-end replication configure a `flood-vtep` for each destination. A `static-mac <mac> remote <address>` entry directs known unicast traffic to a specific VTEP.

## Multiple VNIs on one bridge port

An external VXLAN interface can carry several segments on one device. Each mapping admits the VLAN on the bridge port and translates between the local VLAN and the on-wire VNI. The optional receive filter admits the mapped VNIs.

```text
set interfaces bridge br0 vlan-filtering
set interfaces bridge br0 member interface vxlan0
set interfaces vxlan vxlan0 source-address 192.0.2.1 destination-port 4789
set interfaces vxlan vxlan0 external vni-filter
set interfaces vxlan vxlan0 external vlan 10 vni 10010
set interfaces vxlan vxlan0 external vlan 20 vni 10020
```

The mapping classifies frames. Forwarding external-mode traffic to another VTEP also requires a remote forwarding entry for that VNI. Each mapping can be added, changed or removed independently.

```text
show interfaces vxlan
show interfaces vxlan vxlan0
show interfaces vxlan vxlan0 vni
show interfaces vxlan vxlan0 fdb
show interfaces bridge br0 vlan
```

Linux fixes some properties at creation, including the VNI, fixed or external mode, UDP port range and destination port, checksum flags, and the underlay address family. A bound tunnel can switch underlay devices. Linux cannot clear a device binding in place, so transitioning between bound and unbound requires recreation for reversible commits. Commit check identifies these changes. Changes to a same-family remote VTEP, static forwarding entries or VLAN mappings apply on the existing interface.
