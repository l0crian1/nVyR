# DHCP servers

For implementation and testing, see the [developer guide](../dev/dhcp-server.md).

nVyR manages Kea DHCPv4 and DHCPv6 as separate instances in the default and named
VRFs. Each instance has its own sockets, control endpoint, and persistent lease
database. This initial implementation covers address allocation and reservations;
Running a DHCP relay, prefix delegation, dynamic DNS, and router advertisements
are separate features. The DHCP server can serve requests forwarded by an external
relay.

## Configuration

```text
set service dhcp-server listen-interface eth1

set service dhcp-server shared-network OFFICE subnet 192.168.10.0/24 range 192.168.10.100-192.168.10.150
set service dhcp-server shared-network OFFICE subnet 192.168.10.0/24 range 192.168.10.200-192.168.10.250

set service dhcp-server shared-network OFFICE subnet 192.168.10.0/24 option default-router 192.168.10.1

set service dhcp-server shared-network OFFICE option name-server 192.168.10.1
set service dhcp-server shared-network OFFICE option domain-search example.net

set service dhcp-server shared-network OFFICE subnet 192.168.10.0/24 reservation PRINTER mac-address 02:00:00:00:00:01
set service dhcp-server shared-network OFFICE subnet 192.168.10.0/24 reservation PRINTER address 192.168.10.50
```

Repeat `range` for disjoint pools. Add another `subnet` under OFFICE to expand the
shared link's address space. The router still needs routing/addressing appropriate
for every subnet it serves. An optional `shared-network OFFICE interface eth1`
explicitly selects OFFICE for clients arriving on eth1 and also enables listening
on that interface.

Use `listen-address 192.168.10.1` instead of `listen-interface eth1` to select a
particular local address. nVyR resolves it within the server's VRF. Do not configure
both selectors for the same interface. One address-qualified listener per interface
is supported. An IPv4 interface listener chooses its first IPv4 address and, in
the default raw mode, opens one broadcast socket, avoiding duplicate replies on
interfaces with secondary addresses. DHCPv6 address listeners add a unicast socket
alongside link-local and multicast reception. Their values must be non-link-local unicast IPv6 addresses;
unspecified, multicast and link-local values are rejected at CLI entry and when
loading configuration.

### DHCPv4 socket type

`socket-type` selects how all DHCPv4 listeners in an instance receive requests:

- `raw` (default) receives direct client broadcasts and relayed requests on the
  listening interface. For relayed unicast traffic, target the address selected
  on the interface where the packets arrive.
- `udp` receives relayed requests through normal IP routing, including packets
  addressed to a dummy or loopback interface that arrive through another port.
  It does **not** receive direct client broadcasts.

For a relay targeting a local dummy address:

```text
set interfaces dummy dum0 address 10.0.0.1/32

set service dhcp-server socket-type udp
set service dhcp-server listen-address 10.0.0.1
set service dhcp-server listen-interface eth1

set service dhcp-server shared-network CLIENTS subnet 10.0.101.0/24 range 10.0.101.100-10.0.101.200
set service dhcp-server shared-network CLIENTS subnet 10.0.101.0/24 option default-router 10.0.101.1
```

Configure the relay to forward to `10.0.0.1`. Kea uses the relay's gateway address
to select the client subnet. Ensure the router can route replies to that relay.
Include the interface used to reach the relay (`eth1` in this example) among the
listeners so Kea has a suitable IPv4 socket for its replies.

Selecting `listen-address` does not automatically select UDP. For an instance
serving both direct and relayed clients, keep `raw` and target the receiving
interface's selected address from the relay. Socket type is per instance, not
per listener; it cannot be mixed within an instance. DHCPv6 always uses UDP and
does not have this setting.

```text
set service dhcp-server socket-type raw

show dhcp-server listeners
```

Deleting `socket-type` restores `raw`. The same setting is available under
`vrf name <name> service dhcp-server`.

### VRF instances

Server configuration is also available under a VRF, except `update-hostfile`:

```text
set vrf name BLUE table 101

set interfaces ethernet eth2 vrf BLUE
set interfaces ethernet eth2 address 192.168.20.1/24

set vrf name BLUE service dhcp-server listen-interface eth2

set vrf name BLUE service dhcp-server shared-network OFFICE subnet 192.168.20.0/24 range 192.168.20.100-192.168.20.250
```

### High availability

HA is available for both `dhcp-server` and `dhcpv6-server`, globally and under
`vrf name <name> service`. It synchronizes leases; it does not copy configuration
between routers. **Configure matching pool ranges on every member.** Keep subnet,
reservation and DHCP option definitions consistent too. Each HA commit prints a
warning reminding you that the local and remote pool ranges must match.

On the primary router, using the OFFICE pool configured above:

```text
set service dhcp-server ha name ROUTER1 source-address 192.168.10.1 role primary

set service dhcp-server ha peer ROUTER2 address 192.168.10.2 role secondary
```

On the secondary router, with the same OFFICE subnets and ranges:

```text
set service dhcp-server ha name ROUTER2 source-address 192.168.10.2 role secondary

set service dhcp-server ha peer ROUTER1 address 192.168.10.1 role primary
```

`ha mode` defaults to `active-active` only when HA is configured. Both members
serve clients. nVyR splits each configured range into two nonoverlapping portions:
the primary owns the lower portion and the secondary owns the upper portion.
Both routers generate the same assignments regardless of which role is local.
For `192.168.10.100-192.168.10.150`, the primary portion is `.100-.125` and the
secondary portion is `.126-.150`. The original CLI range remains unchanged.

An odd extra address belongs to the primary. A single-address range belongs
entirely to the primary. A new range gets its own split without moving the
boundaries of existing ranges. While both peers are healthy, each serves its
assigned portion; when Kea declares a partner down, the survivor can serve both.

For active-passive, use a primary and a standby on both routers:

```text
set service dhcp-server ha mode active-passive
set service dhcp-server ha peer ROUTER2 role standby
```

On ROUTER2:

```text
set service dhcp-server ha mode active-passive
set service dhcp-server ha role standby
```

Active-passive keeps the complete ranges unsplit. Additional replicas can be
configured with role `backup`; they receive lease updates but do not take over
automatically. A backup's configuration must include both serving members.

Local and remote ports can differ. Defaults are TCP **8005 for DHCPv4** and
**8006 for DHCPv6**. A custom local port does not change the default peer port:

```text
set service dhcp-server ha port 9005

set service dhcp-server ha peer ROUTER2 port 9006
```

DHCPv6 and VRF examples use the same subtree:

```text
set service dhcpv6-server ha name ROUTER1 source-address 2001:db8:10::1 role primary

set service dhcpv6-server ha peer ROUTER2 address 2001:db8:10::2 role secondary
```

```text
set vrf name BLUE service dhcp-server ha mode active-passive name ROUTER1 source-address 192.168.20.1 role primary

set vrf name BLUE service dhcp-server ha peer ROUTER2 address 192.168.20.2 role standby
```

The HA address is a local listener address in the server's VRF and may use either
IP family, independently of the DHCP family. IPv6 link-local addresses are not
supported for HA peer URLs. Allow the configured TCP ports between peers. This
initial implementation uses HTTP, so keep that communication on a trusted network.
Kea's normal heartbeat and client-failure detection govern takeover; a successful
commit does not mean that the peer is reachable or that synchronization finished.

### Local lease hostnames

Publish active DHCPv4 lease hostnames in the router's `/etc/hosts`:

```text
set service dhcp-server update-hostfile

set service dhcp-server shared-network OFFICE option domain-name home.example
```

A client reporting `printer` appears as `printer.home.example` with `printer` as
an alias. Subnet domain options override shared-network options, which override
server options. A client reporting a fully qualified name keeps that domain.
Without a domain, a short hostname stays a short hostname. Reservation hostnames
are published once the reservation has an active lease.

This setting is available only on the **global DHCPv4 server**. The hosts file
has no VRF namespace, so named-VRF leases and DHCPv6 leases are not published.
This provides local name resolution; it does not configure a DNS server or DDNS.

Lease renewals update hostnames. Released, declined, expired and removed-subnet
leases are omitted. Changes are reconciled at commit and periodically afterward.

Static entries, localhost and the router hostname are preserved. DHCP aliases
that conflict with existing static names are omitted. Invalid client hostnames
are ignored. Hostname updates preserve the router
hostname. A lease-file read error preserves existing entries and reports a
failure, rather than treating the database as empty.

Remove the option, disable the server, or delete the server to remove its managed
hosts section:

```text
delete service dhcp-server update-hostfile
commit
```

### DHCPv6

DHCPv6 uses `dhcpv6-server`, IPv6 prefixes/ranges and DUID reservations:

```text
set service dhcpv6-server listen-interface eth1

set service dhcpv6-server shared-network OFFICE subnet 2001:db8:10::/64 range 2001:db8:10::100-2001:db8:10::ffff

set service dhcpv6-server shared-network OFFICE option name-server 2001:db8:10::1

set service dhcpv6-server shared-network OFFICE subnet 2001:db8:10::/64 reservation PRINTER duid 00:03:00:01:02:00:00:00:00:01
set service dhcpv6-server shared-network OFFICE subnet 2001:db8:10::/64 reservation PRINTER address 2001:db8:10::50
```

For directly connected DHCPv6 clients, Kea requires an interface selector for the
shared network. nVyR derives it when exactly one listening interface has a local
address inside its active subnets; otherwise configure `shared-network OFFICE
interface eth1` explicitly. This also permits a link-local-only server interface.

## Inheritance and validation

Server, shared-network and subnet scopes support `description`, `disable`, timers,
and `option`. More specific options/timers override inherited values. DHCPv4
`lease-time` defaults to `1d`; DHCPv6 `preferred-lifetime` defaults to `12h` and
`valid-lifetime` to `1d`. These are direct defaults, not explicit saved settings.
Durations accept positive whole values with `s`, `m`, `h`, or `d`, up to
4,294,967,294 seconds.

IPv4 options are `default-router`, `name-server`, `domain-name`, `domain-search`,
and `ntp-server`. IPv6 offers `name-server` and `domain-search`. DNS servers, search
domains and IPv4 NTP servers are multi-value settings. Reservations require an
address and one identifier: `mac-address` or `client-id` for IPv4; `duid` for IPv6.
They also accept `hostname` and `description`.

The `option` node is anchored at server, shared-network and subnet scope, including
inside VRFs. Multiple options can be entered in one command:

```text
set service dhcp-server shared-network OFFICE option name-server 1.1.1.1 default-router 192.168.10.1
```

Reservation nodes are also anchored for both families. For example, a reservation
can be configured on one line:

```text
set service dhcp-server shared-network OFFICE subnet 192.168.10.0/24 reservation PRINTER mac-address 02:00:00:00:00:01 address 192.168.10.50 hostname printer
```

Verification rejects overlapping subnets in one VRF, overlapping/out-of-subnet
ranges, unusable IPv4 network/broadcast allocations, duplicate reservations,
invalid lifetime relationships, and ambiguous or unavailable listeners. Client
subnets may overlap across VRFs. For now, the **default VRF and a named VRF may
not listen on the same IPv4 address**, because Kea's fallback socket cannot bind
that combination. See [KEA-001](../dev/upstream-issues.md#kea-001-ipv4-default-vrf-fallback-socket-collides-with-a-named-vrf).

`commit check` performs configuration checks and reports that live listener checks
are deferred until commit, after interface owners have run.

For live pools, reservations, leases, statistics and client observations, see
[DHCP operational views](dhcp-operations.md).


## Link availability and retained leases

Administratively enabled ports without carrier are accepted at commit and boot.
The server reports that it is waiting and begins serving automatically when the
link is ready. DHCPv6 also waits for a usable link-local address. Disabled listeners
and unrelated socket failures remain errors.

Deleting or disabling a server stops it but retains its lease database. Reconfiguration
preserves leases; changes to listening addresses may briefly interrupt service.
