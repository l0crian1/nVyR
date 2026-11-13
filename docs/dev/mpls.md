# MPLS and LDP ownership

`protocols_mpls.py` gathers the effective MPLS section, generates a sorted input
membership list and label capacity, then submits it to netlinkd. The schema supplies
the 1,048,575 default; the lifecycle does not duplicate that default.

`nvyr-mpls.service` loads `mpls_router` and `mpls_iptunnel` before netlinkd starts.
Netlinkd owns `/proc/sys/net/mpls`: it grows the table before enabling inputs and
disables removed inputs before shrinking the table. Its existing serialized RPC
and state journal record desired membership and pending before/after values.
Link notifications reapply desired input flags after recreation. No FRR
`mpls enable` or `mpls disable` commands are generated, avoiding competing owners.

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
The FRR recipe digest covers the patch and the package revision is `+nvyr6`.

## Verification

- Unit tests check membership, table capacity, failed/interrupted updates,
  interface-event replay, schemas, native command tokens and nested ownership.
- Native FRR tests run isolated processes in one namespace and check configure,
  edit, remove and recreate, including timer inheritance and sync overrides.
- Smoketests retain one interface pair and check configuration translation and
  sysctls without waiting for sessions or forwarding traffic.
- The shared routed functional suite adds one default-VRF link to its existing
  right-side simulated host. LDP and OSPF share that peer; explicit-null labels
  permit IPv4/IPv6 packet capture to prove labeled delivery.
- Acceptance retains MPLS membership, dual-stack LDP configuration and finite
  IGP hold-downs across reboot on its existing transit interface.
