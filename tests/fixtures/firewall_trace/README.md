# Native trace regression corpus

`linux-6.18-nft-1.1.7.json` contains unmodified native trace lines and chain
metadata from 25 synthetic traffic scenarios on Linux 6.18.58-nvyr-amd64 with
nftables 1.1.7. Captured on 2026-10-26 using `tests.trace_lab` in isolated
network namespaces on the development router. No home-network or management
traffic is included.

The fixture omits userspace receive timestamps and duplicate parsed fields.
Tests rebuild capture envelopes around the retained evidence. It includes
1,288 events covering TCP, UDP, ICMP/ICMPv6, both address families, nested
jumps/returns/goto, zones, sets and verdict maps, NAT address and port rewrites,
notrack, ingress, VRF output, default policies, reject responses, state policies,
marks, fail-safe tables and named stateful objects.

`empty-and-unmatched.json` adds 20 native events from four loopback ICMP
packets on the same kernel and nftables version, captured on 2026-10-26 in an
isolated namespace. The output chain jumps to an empty chain, then a chain
containing a nonmatching destination-address rule, and finally accepts. Neither
target emits its own event; the subsequent caller rule proves the return.
This fixture verifies that the itinerary retains both targets without inventing
rule hits. The native lab also covers this case on the forwarding path.

Run the opt-in native lab in a new directory to collect fresh evidence:

```bash
sudo env PYTHONPATH=src:. unshare -n python3 -m tests.trace_lab /tmp/nvyr-trace-lab
```

The regular regression test replays these records without network privileges.
It checks actual outcomes and observations, not machine-specific trace IDs,
MAC addresses, dynamically allocated ports or native rule handles.
