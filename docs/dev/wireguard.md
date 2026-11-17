# WireGuard implementation

`interface_wireguard.py` owns the configuration lifecycle. `get_config()` gathers
WireGuard interfaces, VRFs and bridge/bond membership. `verify()` checks the
relationships that individual CLI validators cannot: required key identities,
unique local listen ports, duplicate peer keys and exact allowed-prefix ownership,
endpoint pairs and hostname-only controls. Common netlink validation checks link
ownership and IP settings before application.

`generate()` canonicalizes allowed prefixes, resolves changed hostname endpoints
with bounded concurrency, and creates native link definitions and scheduler units.
`apply()` replaces the WireGuard owner's link definitions and reconciles its
feature-owned timers. Configd does not configure WireGuard itself.

## Native synchronization

The `wireguard` netlink driver uses the normal link manager for creation, address
assignment, VRF membership, common IP controls, removal, rollback and recreation.
It calls `helpers/wireguard.py` for native `wg syncconf` application. A private
temporary file, rendered with `templates/wireguard/interface.conf.j2`, carries
the secrets and is removed in `finally`. Keys do not appear in command arguments.

The endpoint manifest in `/run/nvyr-netlink/wireguard/<interface>.json` contains
only public keys, endpoint intent and the selected endpoint. It has no private
or preshared keys. This is needed to distinguish an unrelated commit from an
endpoint edit: WireGuard can change its live endpoint through authenticated
roaming, so blindly restoring the original address would interrupt a valid peer.
A per-interface lock serializes reconciliation and manual/scheduled refresh.
Existing protected netlink state contains the complete desired configuration,
including keys, so recreation can restore the interface without configd replay.

Synchronization reads native state immediately before rendering, keeps unchanged
roaming endpoints and automatic ports, and does not mutate the supplied desired
configuration. Native `syncconf` retains unchanged peers and their sessions.
Synchronization compares native keys, peers and settings before calling the tool;
an unchanged application must not produce link notifications and trigger another
netlink reconciliation. Private-key comparison accounts for X25519 scalar clamping.
Removing a configured endpoint requires removing that peer before synchronization:
omitting Endpoint alone preserves its previous native value. An empty AllowedIPs
line is rejected by Debian's tool, so empty prefixes are represented by omission;
`syncconf` clears them. Both behaviors have native smoketest coverage.

DNS refresh uses the shared scheduler under owner `wireguard`. A short hash of
the peer name keeps the generated systemd task identity within scheduler limits;
the actual peer name remains in the command. DNS lookups share a three-second
deadline per peer. Up to eight peers resolve concurrently. Refresh avoids recent
handshakes using the same 135-second criterion as WireGuard's upstream
[reresolve-dns example](https://git.zx2c4.com/wireguard-tools/tree/contrib/reresolve-dns/reresolve-dns.sh).
Manual refresh overrides that skip. Errors are visible in operational output or
the existing task logs, while the last endpoint is retained.

Each enabled interface with hostname peers also has an initial-resolution oneshot
service. It retries failures every 15 seconds through systemd and exits once all
those peers have endpoints. Starting it is nonblocking: interface creation cannot
wait for DNS or routing configured later in boot. Already resolved or roaming peers
are skipped. Removing or disabling the interface removes the service through the
same scheduler owner. The runtime manifest retains a refreshed endpoint for native
interface recreation without changing the generated configuration dictionary.

## Dependencies and maintenance

Use the kernel WireGuard implementation and Debian trixie's `wireguard-tools`
package. No `wg-quick`, userspace tunnel process, external repository, or native
patch is needed. The kernel module is loaded through native link creation.
The tools project remains maintained upstream; the Debian release carries the
distribution package and its fixes. See the
[Debian source package](https://tracker.debian.org/pkg/wireguard) and
[upstream tools history](https://git.zx2c4.com/wireguard-tools/log/).
Recheck both when changing the Debian base or tool version.

The transport socket belongs to the default network namespace. Moving the
interface into a network VRF changes inner routing, not the socket's transport
VRF. Front-door VRFs and namespace-backed transport are intentionally deferred.

## Tests

- `tests/test_wireguard.py`: endpoint-intent preservation, DNS deadline and failure
  handling, scheduled/manual refresh differences and configuration validation.
- `smoketests/test_wireguard.py`: one retained interface/VRF; native settings,
  peer/key/allowed-prefix removal, roaming preservation, disable, recreation,
  hostname failure, scheduler lifecycle and operational secret handling.
- `functionaltests/network/test_wireguard.py`: the shared routed scenario supplies
  two tunnel pairs, IPv4/IPv6 transport, both inner families, a PSK and inner VRF.
  A third peer shares the VRF tunnel to exercise overlapping IPv4 /8 and /24,
  IPv6 /48 and /64, and default prefixes. Bidirectional traffic and per-peer
  counters check selection; receive-error counters verify wrong-peer source rejection.
- `functionaltests/network/test_wireguard_routing.py`: reuses those peers for
  overlapping static routes, competing next-hop distances, route withdrawal,
  peer outage/recovery, and IPv4/IPv6 BGP sessions over the tunnel. Kernel route
  lookups identify the selected next hop; packet captures identify the actual
  decrypting peer. ICMP probes demonstrate both successful delivery and deliberate
  route/AllowedIPs conflicts, including recovery after correcting AllowedIPs.
  These are namespace peers on one router, not separate physical WireGuard routers.
- `acceptance/config/wireguard.set`: reciprocal local peers across default and
  BOOTLEFT routing domains; keys, settings and dual-stack traffic are verified
  before and after save/reboot.
