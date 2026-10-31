# Interface configuration

For implementation and testing, see the [developer guide](../dev/interfaces.md).

Configure physical and virtual interfaces, their addresses, VLANs, VRF membership,
and link groups. Use [interface diagnostics](interface-operations.md) to inspect live state.

## Current commands

### IPv4 and IPv6 options

Anchored `ip` and `ipv6` nodes are shared by Ethernet, dummy, virtual Ethernet,
bridge, and their supported VIFs. Loopback retains its address/description-only
interface. VIF settings belong to that VIF; they do not inherit the parent's
overrides. Common settings inherit `firewall global-options` unless explicitly
overridden on the interface. Deleting an override restores that inheritance.

ARP modes include descriptions in completion output:

- `arp-ignore 0`: reply for any local target address, including one on another interface.
- `arp-ignore 1`: reply only if the target belongs to the receiving interface.
- `arp-ignore 2`: additionally require the sender to be in that target's subnet.
- `arp-ignore 3`: exclude host-scope target addresses; allow global and link scope.
- `arp-ignore 8`: never reply for local target addresses.

These values mean the same thing on every supported interface type. IPv4 syntax:

```text
set interfaces ethernet eth1 ip receive-redirects enable|disable
set interfaces ethernet eth1 ip send-redirects enable|disable
set interfaces ethernet eth1 ip source-route enable|disable
set interfaces ethernet eth1 ip directed-broadcast enable|disable
set interfaces ethernet eth1 ip log-martians enable|disable

set interfaces ethernet eth1 ip arp-ignore 0|1|2|3|8
set interfaces ethernet eth1 ip arp-announce any|subnet|best-local
set interfaces ethernet eth1 ip arp-accept disable|enable|same-subnet
set interfaces ethernet eth1 ip arp-filter enable|disable
set interfaces ethernet eth1 ip arp-notify enable|disable
set interfaces ethernet eth1 ip arp-proxy enable|disable
set interfaces ethernet eth1 ip arp-proxy-pvlan enable|disable
set interfaces ethernet eth1 ip arp-cache-timeout <duration>
set interfaces ethernet eth1 ip arp-retransmit-interval <duration>
set interfaces ethernet eth1 ip arp-stale-time <duration>

set interfaces ethernet eth1 ip disable-forwarding
set interfaces ethernet eth1 ip accept-local
set interfaces ethernet eth1 ip route-localnet
set interfaces ethernet eth1 ip promote-secondaries
```

`arp-announce` selects the source address of outgoing ARP requests: `any` permits
any local address, `subnet` prefers the target subnet, and `best-local` selects
the best address for that target. `arp-accept` controls learning new neighbors
from gratuitous ARP. `arp-filter` consults routing before answering requests.
Proxy ARP answers for routed destinations; `arp-proxy-pvlan` permits answering
back through the receiving interface. `arp-notify` sends gratuitous ARP when a
link comes up or its MAC changes.

IPv4 forwarding is enabled unless disabled here. `accept-local` permits local
source addresses arriving from another interface; `route-localnet` allows routed
127.0.0.0/8 traffic. `promote-secondaries` retains secondary addresses when their
primary is removed. Those three behaviors are otherwise disabled.

IPv6 syntax:

```text
set interfaces ethernet eth1 ipv6 disable
set interfaces ethernet eth1 ipv6 receive-redirects enable|disable
set interfaces ethernet eth1 ipv6 source-route disable|routing-header-2
set interfaces ethernet eth1 ipv6 proxy-ndp
set interfaces ethernet eth1 ipv6 hop-limit <1-255>

set interfaces ethernet eth1 ipv6 autoconf
set interfaces ethernet eth1 ipv6 accept-router-advertisements
set interfaces ethernet eth1 ipv6 no-default-route
set interfaces ethernet eth1 ipv6 no-ra-mtu

set interfaces ethernet eth1 ipv6 eui64 <IPv6-network/64>
set interfaces ethernet eth1 ipv6 interface-identifier <identifier>
set interfaces ethernet eth1 ipv6 address-generation eui64|stable-privacy
set interfaces ethernet eth1 ipv6 link-local-address <link-local-address>
set interfaces ethernet eth1 ipv6 no-default-link-local

set interfaces ethernet eth1 ipv6 temporary-addresses disable|prefer-public|prefer-temporary
set interfaces ethernet eth1 ipv6 maximum-autoconf-addresses <1-65535>

set interfaces ethernet eth1 ipv6 duplicate-address-detection disable
set interfaces ethernet eth1 ipv6 duplicate-address-detection probes <1-100>

set interfaces ethernet eth1 ipv6 neighbor-reachable-time <duration>
set interfaces ethernet eth1 ipv6 neighbor-retransmit-interval <duration>
set interfaces ethernet eth1 ipv6 neighbor-stale-time <duration>
```

IPv6 stays enabled by default, with automatic link-local addressing, EUI-64
generation, one DAD probe, hop limit 64, and a maximum of 16 autoconfigured
addresses. SLAAC, RA reception, temporary addresses and proxy NDP are off.
`proxy-ndp` enables proxy behavior; it does not create proxy neighbor entries.

`autoconf` enables SLAAC and RA reception even while forwarding.
`accept-router-advertisements` enables RA reception without SLAAC. `no-default-route`
and `no-ra-mtu` require one of those options. An explicit hop limit takes priority;
otherwise an RA can supply it. Removing RA acceptance withdraws learned RA routes.
Disabling default-route learning also removes an already learned default.

For example, obtain addresses using a fixed host identifier without installing
the advertised default route:

```text
set interfaces ethernet eth1 description "SLAAC LAN"

set interfaces ethernet eth1 ipv6 autoconf
set interfaces ethernet eth1 ipv6 interface-identifier ::1234
set interfaces ethernet eth1 ipv6 no-default-route
```

`eui64` is repeatable. It creates static addresses from each /64 and the current
MAC, without requiring an RA. Changing the MAC replaces those derived addresses.
`interface-identifier` supplies a nonzero lower-64-bit SLAAC token and requires
`autoconf`. Linux does not support tokens on dummy devices, so that leaf is
unavailable on dummy interfaces. Temporary addresses also require `autoconf`; the preference chooses
public or temporary source addresses. Reconciliation preserves SLAAC and
temporary-address lifetimes.

```text
set interfaces dummy dum1 mac 02:00:00:12:34:56

set interfaces dummy dum1 ipv6 eui64 2001:db8:10::/64
set interfaces dummy dum1 ipv6 eui64 2001:db8:20::/64
set interfaces dummy dum1 ipv6 link-local-address fe80::1234
```

An explicit link-local address replaces automatic link-local generation.
`no-default-link-local` suppresses generation while allowing a manually configured
link-local address. Stable-privacy generation uses a private seed stored in
`/config/ipv6-stable-secret.json`, retained over reboot and image upgrades, with a
distinct derived secret for each interface. It cannot be combined with a fixed
token, explicit link-local address, or link-local suppression: Linux's suppression
mode selects EUI-64 for SLAAC. IPv6 disable cannot coexist with IPv6 addresses or
other IPv6 options. DAD disable and probe count are mutually exclusive.

Reachability and retransmit durations accept `ms`, `s`, `m`, `h`, or `d`, up to
2,147,483,647 milliseconds. Stale-neighbor intervals accept `s`, `m`, `h`, or `d`,
up to 2,147,483 seconds. Values must be positive. Defaults are 30 seconds reachable,
1 second retransmit, and 60 seconds stale; the IPv4 reachable default can also
come from the firewall global ARP setting.

### System loopback

```text
set interfaces loopback lo address 192.0.2.1/32
set interfaces loopback lo address 2001:db8::1/128
set interfaces loopback lo description "Router identity"
```

The `lo` instance is anchored and supports multiple static IPv4/IPv6 addresses
and a description. It has no DHCP, disable, MTU, VRF or VLAN settings. The kernel
device is never created or deleted by nVyR. Removing its configuration clears
the configured addresses and alias while retaining `127.0.0.1/8`, `::1/128` and
the up state. Those system addresses retain their prefix lengths even when
explicitly configured and then removed. Additional logical interfaces can use
the dummy interface type.

### DHCPv4 client lease control

```text
release dhcp interface eth1

renew dhcp interface eth1
renew dhcp interface br0
renew dhcp interface eth1.10
```

These operational commands require net-admin access and an enabled, managed
DHCPv4 client. They also work through `run` in configuration mode. They control
the interface's client lease, not a DHCP server reservation.

Release asks the client to return its lease and enter the released state. The
normal lease hook removes DHCP-provided addresses, routes and resolver entries;
static configuration is retained. Renew requests renewal of an existing lease
or starts acquisition after release. Both report that the request was sent;
receiving a new lease still depends on the server.

The configuration remains unchanged. A released client stays released during
normal reconciliation, but restarting/recreating that client or rebooting
resumes acquisition because `address dhcp` is still configured. IPv6 DHCP client
control remains deferred along with DHCPv6 client support.

### DHCPv4 client options

`dhcp-options` is anchored and available on Ethernet, bridges, and their supported
VIFs (including virtual-Ethernet VIFs). It controls DHCPv4 only:

```text
set interfaces ethernet eth1 address dhcp

set interfaces ethernet eth1 dhcp-options client-id text "WAN client"
set interfaces ethernet eth1 dhcp-options host-name edge.example
set interfaces ethernet eth1 dhcp-options vendor-class-id "ISP vendor"
set interfaces ethernet eth1 dhcp-options user-class customer

set interfaces ethernet eth1 dhcp-options default-route-distance 210
set interfaces ethernet eth1 dhcp-options mtu
set interfaces ethernet eth1 dhcp-options no-default-route
```

Alternatively, `client-id hex 01:02:00:00:00:00:01` supplies the complete identifier,
including its type byte. Exactly one of `text` and `hex` may be configured. Text
uses type zero followed by UTF-8 bytes; without an override udhcpc uses its normal
MAC-based identifier. User class uses the RFC 3004 length-prefixed encoding.
The hostname defaults to the system hostname at client startup.
The combined encoded identity fields are limited to 240 bytes, including their
option headers and the default client ID when used. This leaves room for the
protocol's own options in udhcpc's 308-byte transmit buffer; an oversized
combination fails verification instead of silently omitting fields.

The DHCP default-route administrative distance is **210**, configurable from 1 to
254. Ordinary static routes (AD 1) therefore take precedence. This applies to defaults
from both the router and classless-route options. `no-default-route` suppresses
both forms while retaining other advertised routes.

`mtu` opts into DHCP option 26. Without it, server MTU offers are ignored. If no
MTU is offered, or the lease expires/is released, the configured interface MTU
returns (VIFs inherit their parent's MTU when no override is configured).
Offered MTUs must fit nVyR's 1280–65535 range, parent limits and kernel device
limits. Disabling the option restores the configured MTU without renegotiating.

Identity changes restart the client with a new generation. Route-distance,
default-route and MTU policy changes apply to the current lease without restarting
it. Server rejection is deliberately not exposed.

### Bridges

See [Bridge interfaces](bridges.md) for membership, VLAN switching, native STP,
MAC/multicast policy and operational commands.

### VLAN subinterfaces

Ethernet, virtual Ethernet and bridges support anchored `vif <VLAN ID>` instances:

```text
set interfaces ethernet eth1 vif 10 address 10.0.10.1/24 description "Users"
set interfaces ethernet eth1 vif 10 vrf BLUE link-group 10
set interfaces ethernet eth1 vif 20 address dhcp

set interfaces virtual-ethernet veth0 peer-name veth1
set interfaces virtual-ethernet veth1 peer-name veth0

set interfaces virtual-ethernet veth0 vif 30 address 10.0.30.1/24
```

These create `eth1.10`, `eth1.20`, and `veth0.30`. IDs are 1–4094 without leading
zeros, and the complete generated name must fit Linux's 15-character limit.
Each child supports description, disable, IPv4/IPv6 addresses, DHCPv4, MAC, MTU,
VRF and link-group. VRF assignment is independent of the parent. An omitted MTU
tracks the parent's current MTU; an explicit MTU cannot exceed the parent.
Nested anchored options remain on the VIF; configure parent options in a separate
command when the parent and child share the same option name.

VIFs register their complete names as interface dependencies. References protect
both individual VIF deletion and deletion of their parent. Candidate interface
suggestions include VIF names before commit, and firewall VRF matching recognizes
VIF membership. An empty VIF is a valid enabled VLAN interface.

Parents are created before children and removed after them. Ordinary edits
preserve interface indices. QinQ and nested VIFs are not supported.

### Base interfaces

```text
set interfaces ethernet eth0 address 192.0.2.10/24 address 2001:db8::10/64
set interfaces ethernet eth0 address dhcp
set interfaces ethernet eth0 mac 02:11:22:33:44:55 mtu 9000 description "Core uplink"

set interfaces dummy dum0 address 192.0.2.1/32
set interfaces dummy dum0 disable

commit
save
```

### Virtual Ethernet pairs

A virtual Ethernet pair connects two software endpoints. Configure both endpoints
with reciprocal peer names; each endpoint has its own addresses, description,
MAC, MTU, administrative state, VRF and link-group settings.

```text
set interfaces virtual-ethernet veth0 peer-name veth1
set interfaces virtual-ethernet veth1 peer-name veth0

set interfaces virtual-ethernet veth0 description "BLUE side" address 192.0.2.1/30
set interfaces virtual-ethernet veth1 description "RED side" address 192.0.2.2/30
```

Names use `veth` followed by 1–11 digits. Both endpoints must be configured and
must name each other. The manager creates and removes the pair as one lifecycle
unit. Ordinary attribute changes preserve the pair; changing an existing peer
requires deleting and committing the pair first. Remove both endpoints together.
VLAN subinterfaces can be created beneath either endpoint. These managed pairs
are separate from the veth devices created by Netavark for containers.

### VRFs and link groups

Netlinkd maintains IPv4 and IPv6 policy rules when configuring a VRF: priority
1000 looks up its routing table, priority 2000 returns unreachable for VRF traffic
with no route, and priority 32765 looks up the default local table. This lets a
veth pair connect the default routing instance to a VRF without local delivery
intercepting the packet, while preventing fallback from a VRF into the main table.
Netlinkd repairs these rules during reconciliation. They remain after the last
VRF is deleted; the VRF-specific rules do not match traffic in the default instance.

Each named VRF also receives an automatic conntrack zone. Zone 0 remains the
default routing instance. A shared interface-to-zone map in the separate
`inet nvyr_vrf_conntrack` table isolates locally generated and incoming IPv4/IPv6
connections, including NAT across a veth pair between routing instances.
Ethernet, dummy, veth, bridge, VIF and container-network bridge membership all use
the same map. VIFs use their own configured VRF, not their parent's assignment.

The `vrf_conntrack` script installs the map before changed interface providers
apply. Its prerouting/output chains run at priority -250, after raw rules and
before conntrack; packets marked `notrack` are left untracked. The automatic table
exists independently of normal and fail-safe firewall rules.

Zone IDs are allocated independently of routing table IDs, which may be larger
than 65535. Allocations survive commits, failed applies and daemon restarts.
Removed identities retain their reservations until reboot, so a different VRF
cannot inherit old connection state. Recreating the same name and table retains
the same identity. The ledger lives in configd's state directory as
`vrf-conntrack.json`. Changing membership moves new connections into the new zone;
existing connections may need to be reestablished after a VRF move.

VRF devices are created through the same Netlink lifecycle:

```text
set vrf name BLUE table 100
set vrf name RED table 256

commit
save
```

Each VRF requires a unique routing table ID in 100–251 or 256–4294967295.
Names follow Linux interface naming constraints (1–15 characters, beginning with
a letter); `default` is reserved for the default routing instance. VRFs are brought
up automatically and recreated if externally deleted. Removing their configuration
deletes the devices. An existing VRF's table cannot be changed in place: delete and
commit the VRF first, then recreate it with the new table. Static routes can be
configured beneath `vrf name <name> protocols static`; see [static routing](static.md#vrf-routing).
Ethernet, dummy, virtual Ethernet, bridge and VLAN interfaces can join a configured
VRF and independently use a Linux link group:

```text
set interfaces ethernet eth1 vrf BLUE link-group 10
set interfaces dummy dum0 vrf BLUE link-group 10
```

Membership requires the target VRF in the proposed configuration. The dependency
checks prevent deleting a VRF while interfaces reference it. A VRF and its
members can be configured in one commit. Removing the `vrf` leaf returns the
interface to the default routing domain; removing `link-group` assigns group 0.
Link groups are numeric IDs from 0 through 4294967295, need no separate creation,
and can be shared by multiple interfaces. They are distinct from firewall groups.

Linux moves local and connected routes when VRF membership changes. Netlinkd
reasserts configured addresses and installs DHCP routes in the VRF's routing
table, removing its old leased routes from their previous tables. Static routes
remain owned by FRR in their explicitly configured VRF; interface reassignment
does not rewrite static routing configuration. DHCP leases remain valid across
membership changes without an interface bounce. Recovery restores VRFs before
their members and repairs externally changed membership and link groups.

VRF instances cannot be renamed. You can copy a VRF
to a new name and assign a different, unique table ID before committing. Deleting
the old instance remains subject to the normal dependency checks.

### Address and attribute lifecycle

An empty configured interface is up. `disable` takes it down and removes its
addresses; removing disable restores them. Ethernet devices must exist during
normal verification; recovery retains desired configuration for absent ports and
applies it when the correctly named device appears. Dummy links are created,
recreated if lost, and deleted when their configuration is removed. Existing
unowned virtual links are rejected. Dummy MAC defaults are deterministic, locally
administered addresses derived from the name.

Static IPv4/IPv6 addresses are multi-valued. Omitted prefix lengths become /32 or
/128. DHCP is IPv4-only and can coexist with static addresses. Kernel IPv6
link-local addressing and DAD are enabled by default. RA reception and SLAAC are
opt-in through the [IPv6 options](#ipv4-and-ipv6-options). DHCPv6 clients are not supported.

MAC, MTU and alias changes use Netlink. Original attributes are recorded before
application; deleting a MAC or description restores their baseline. The schema's
MTU default remains 1500. Removing Ethernet configuration removes its addresses,
restores the original attributes and leaves the physical link down. It is then
unclaimed. Unconfigured interfaces are not continually managed.


## Troubleshooting changes

Interface changes are not atomic across multiple devices. A failed apply attempts
to restore the previous settings; failed recovery is reported rather than treated
as success. Do not run another network manager against nVyR-managed interfaces.

Inspect normal state with [interface diagnostics](interface-operations.md). For
additional detail during troubleshooting:

```text
set system logging service netlinkd level debug
commit

run show log netlinkd follow
```

Delete the logging override when finished to restore the normal logging level.
