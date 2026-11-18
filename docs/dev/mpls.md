# MPLS and LDP ownership

`protocols_mpls.py` gathers the effective MPLS section. `verify()` checks duplicate
native identities and complete static next-hop actions. `generate()`
produces the kernel settings and renders `frr/mpls.conf.j2`; `apply()` submits the
kernel settings to netlinkd and the native configuration to the shared FRR reload
manager. The kernel capacity is fixed at 1,048,575 when MPLS is enabled. The schema
supplies default TTL 255 and restricts static incoming labels to 16–99999.
Priority 39 establishes these settings before static routes,
LDP and BGP consume labels.

`nvyr-mpls.service` loads `mpls_router` and `mpls_iptunnel` before netlinkd starts.
Netlinkd owns `/proc/sys/net/mpls`: it grows the table before enabling inputs and
disables removed inputs before shrinking the table. Its existing serialized RPC
and state journal record desired membership and pending before/after values.
Link notifications reapply desired input flags after recreation. No FRR
`mpls enable` or `mpls disable` commands are generated, avoiding competing owners.
Netlinkd also applies global TTL propagation/default TTL and restores their Linux
defaults when MPLS configuration is removed.

The MPLS FRR adapter owns only top-level `mpls lsp`
and `mpls fec nexthop-resolution` lines. The static route adapter owns label stacks
on IP routes. Neither adapter owns LDP's nested block or BGP's address families.
The package supplies `frr-zebra.conf` and sets Zebra's explicit `-f` startup file.
This establishes the fixed dynamic range 100000–1048574 before LDP asks Zebra for
its first chunk. Integrated `vtysh -b` and configd replay happen too late for that
initial request. Adapters preserve this system-owned line, including when MPLS
is removed. No nVyR allocator, SRGB reservation, native patch or automatic protocol
restart is introduced. Installing this package on an already-running development
host requires an FRR restart or reboot to apply the startup setting.

`protocols_ldp.py` gathers LDP, MPLS membership, interface configuration and policy
access lists. `verify()` checks relationships; leaf syntax belongs to CLI
validators. `generate()` renders `frr/ldp.conf.j2`; `apply()` uses the shared FRR
reload manager. The LDP adapter owns only the nested `mpls ldp` block, retaining
AF and interface boundaries and preserving unrelated integrated configuration.

OSPF and IS-IS retain ownership of their own LDP-sync process/interface settings.
They are unavailable in named-VRF schema branches because the native sync client
uses the default routing domain. Explicit OSPF override removal uses the patched
native reset command rather than substituting a different configuration meaning.

See [upstream issues](upstream-issues.md) for the FRR fixes and retest criteria.
The FRR recipe digest covers the patches, including local host-route LDP egress
bindings and static IPv6 next-hop resolution exposed by the OSPFv3 forwarding
tests. Pending label updates are also retained when the last connected route
at a RIB destination is removed.
The dual-stack neighbor reset also recreates transport-family state when the
LDP transport preference changes.

## Verification

- Unit tests check membership, table capacity, failed/interrupted updates,
  interface-event replay, schemas, native command tokens and nested ownership.
- Native FRR tests run isolated processes in one namespace and check configure,
  edit, remove and recreate, including timer inheritance and sync overrides.
- Smoketests retain one interface pair and check configuration translation and
  sysctls without waiting for sessions or forwarding traffic.
- The shared routed functional suite keeps a direct MPLS link to its existing
  right-side simulated host. OSPFv2 and OSPFv3 provide loopback reachability;
  IPv6 transport no longer falls back to static routes. Explicit-null labels
  permit IPv4/IPv6 packet capture to prove labeled delivery.
- `network/test_mpls_igps.py` selects OSPFv2/OSPFv3, dual-stack IS-IS, or
  RIP/RIPng on a second PE–P–PE path. The native P router has no BGP or static
  routes. Each profile runs with IPv4 and IPv6 loopback BGP peering and LDP TCP
  transport; operational LDP neighbors on both core links verify that selection.
  Selected IGP routes on all three routers, LDP bindings, labeled kernel routes, and
  two-label packet captures verify VPNv4, VPNv6, IPv4 LU and IPv6 LU in both
  directions. OSPFv2 and IS-IS also require completed LDP synchronization.
  OSPFv3 interface `/128` delivery and peer label withdrawal on address removal
  cover the local-host FEC regression.
  Interfaces, customer VRFs and native processes survive every case; only
  the selected IGP and BGP/LDP transports change.
- Acceptance retains MPLS membership, dual-stack LDP configuration and finite
  IGP hold-downs across reboot on its existing transit interface.
- Static push/swap/pop, recursive LU, uniform/pipe TTL and two-label MTU boundaries
  share the existing routed namespaces. The fixture builds these paths once;
  only TTL tests modify and restore configuration between cases. Fixed ingress
  and egress MTUs allow the boundary tests to share that same topology.
- Acceptance also checks the dynamic block, FEC resolution, TTL and IPv4/IPv6
  static label stacks before and after reboot.
