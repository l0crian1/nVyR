# WireGuard interfaces

WireGuard provides routed, encrypted IPv4 and IPv6 tunnels. A `wgN` interface
can have multiple named peers, IPv4 and IPv6 addresses, and an inner VRF.
Encrypted UDP traffic uses the default routing domain. Front-door VRFs and
separate transport namespaces are not supported in this release.

## Keys and a tunnel

Generate a separate identity on each router:

```text
generate wireguard key-pair
generate wireguard preshared-key
```

Keep the private key on its router. Exchange public keys; an optional preshared
key must match on both peers. These commands only print keys; they do not install
them. Substitute your generated values for the placeholders below:

```text
configure
set interfaces wireguard wg0 private-key <local-private-key>
set interfaces wireguard wg0 listen-port 51820
set interfaces wireguard wg0 address 10.80.0.1/30 address 2001:db8:80::1/64
set interfaces wireguard wg0 description 'Branch tunnel' mtu 1420
set interfaces wireguard wg0 peer branch public-key <remote-public-key>
set interfaces wireguard wg0 peer branch preshared-key <shared-key>
set interfaces wireguard wg0 peer branch allowed-ips 10.80.0.2/32 allowed-ips 10.90.0.0/24 allowed-ips 2001:db8:80::2/128
set interfaces wireguard wg0 peer branch endpoint address 192.0.2.20 port 51820
set interfaces wireguard wg0 peer branch persistent-keepalive 25
set protocols static route 10.90.0.0/24 interface wg0
commit
save
```

The other router needs the reciprocal addresses, public key, allowed prefixes
and endpoint. Permit the UDP listen port in the input firewall. Inner tunnel
traffic is subject to the ordinary input, output and forward policies; use
`wg0` as the interface selector where appropriate.

`allowed-ips` selects the peer for outgoing traffic and restricts source
addresses accepted from that peer. It does **not** install routes. Configure
static routing or a routing protocol separately. Nested prefixes across peers
use longest-prefix selection. The same exact prefix cannot belong to two
enabled peers on one interface.

Routes and AllowedIPs must agree about which peer serves a destination. For
example, if peer A owns `10.0.0.0/8` and peer B owns `10.0.0.0/24`, traffic to
`10.0.0.88` uses peer B even when a static or BGP route through the WireGuard
interface names peer A's tunnel address as its next hop. If that destination
exists only behind A, traffic fails. Removing a more-specific route or changing
route preference does not change this peer selection.

Use separate WireGuard interfaces when routing must select between peers that
can serve the same destinations. On a shared interface, nested AllowedIPs work
for destinations intentionally assigned to different peers; they do not provide
route-controlled failover between those peers.

## Native behavior and optional settings

- Omitting `listen-port`, or setting it to `0`, selects a native automatic port.
  Unrelated commits preserve that port.
- Keepalives default to off. `persistent-keepalive 0` also disables them.
- Without an explicit MTU, the native WireGuard MTU is retained (1420 bytes).
- Endpoints are optional: a peer can learn its endpoint from authenticated
  incoming traffic. Unrelated commits preserve roaming endpoints and handshakes.
- `disable` administratively disables an interface; `peer <name> disable`
  removes that peer from native WireGuard while retaining its configuration.
- Removing a preshared key or all allowed prefixes clears that native setting.
  Removing a configured endpoint recreates that peer to clear its old endpoint;
  it can subsequently learn a new endpoint from authenticated traffic.
- `firewall-mark <mark>` marks the encrypted outgoing UDP packets. It accepts
  decimal or `0x` hexadecimal values. It does not create policy-routing rules.

An inner VRF is selected with the existing interface syntax:

```text
set vrf name BLUE table 100
set interfaces wireguard wg0 vrf BLUE
```

This places decrypted traffic and routes in BLUE. It does not move the UDP
transport into BLUE. MTU, link group, description and applicable IPv4/IPv6
interface controls are also available. WireGuard has no Ethernet MAC address,
ARP entries, VLAN children, or bridge/bond membership.

## Hostname endpoints

```text
set interfaces wireguard wg0 peer branch endpoint address vpn.example.net port 51820
set interfaces wireguard wg0 peer branch endpoint address-family ipv4
set interfaces wireguard wg0 peer branch endpoint resolve-interval 5m
```

Hostname resolution uses the system's configured DNS servers. Family selection
is `auto`, `ipv4`, or `ipv6`; `auto` considers both families and prefers IPv4
when choosing a new endpoint. An existing endpoint remains selected if it is
still an answer. DNS queries share a three-second deadline per peer, and peers
are resolved concurrently in batches of up to eight.

Resolution occurs when the endpoint changes, when it is unresolved, and at boot.
A failure emits a warning and retains an existing endpoint if one is available.
A new peer without a resolved endpoint remains configured and can receive
authenticated incoming traffic. Unresolved hostname endpoints retry every 15 seconds
until they obtain an endpoint, including when DNS or upstream routes are not ready
during boot. The retry job then exits. Without `resolve-interval`, there is no
subsequent periodic refresh. The interval uses the existing task scheduler, not
another daemon.

Scheduled refresh preserves a roaming endpoint when a handshake occurred in
the last 135 seconds. A manual refresh resolves regardless of handshake age:

```text
update wireguard wg0
update wireguard wg0 peer branch endpoint
```

Refresh failures leave the current endpoint in place. Scheduled results and
errors use the task scheduler's per-task logs.

## Inspection

```text
show wireguard
show wireguard wg0 detail
show wireguard wg0 peer branch detail
show interfaces wireguard wg0
show interfaces wireguard wg0 statistics
```

The WireGuard view shows endpoints, handshake age and transfer counters. Detail
adds public keys, allowed prefixes and keepalive settings. It never prints
private or preshared keys. Configuration marks both secret fields as secrets.

Interface recreation restores the configured key and peers through netlinkd.
Handshake state and a dynamically learned endpoint are native runtime state;
they are not persisted across reboot.
