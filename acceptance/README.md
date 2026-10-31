# Save/reboot acceptance tests

Run this suite **from another machine**, against a disposable, installed nVyR VM
with persistent `/config` and console access. It saves configuration and reboots
the router. It is separate from normal smoketests and is not run by package/ISO
builds. Router-side files ship at `/usr/lib/nvyr/acceptance/` in the package/ISO.

From a checkout on the controller machine:

```sh
python -m acceptance.runner run nvyr-lab --ethernet-interface eth1 --container-image alpine --disposable
```

`nvyr-lab` is a hostname; you can also use `administrator@address` (default user:
`nvyr`). Verify/add the
router's host key with a normal SSH login before starting. The controller needs
Python 3.11+. Install the password transport dependency once:

```sh
python -m pip install -r acceptance/requirements.txt
```

Use a dev-admin account: this controller executes test code on the host.
Container CLI roles do not permit SSH command execution.

The runner prompts once for the administrator's password and keeps it only in
memory for the run, including reconnection after reboot. It uses password login
directly; there are no identity files, SSH agent login, or SSH config aliases.
Root SSH can use `--root`. No passwordless sudo setup is needed.
Access is checked before starting preparation; authentication failures do not
change router configuration. The runner never changes SSH or sudo policy.

Useful controller options:

```sh
python -m acceptance.runner run nvyr@192.0.2.10 --ethernet-interface eth1 --container-image alpine --timeout 900 --disposable
```

The controller prints a run UUID and an artifact directory. Each run:

1. Acquires the configuration lock without taking it from another session.
2. Reserves test resources and saves independent running/saved backups under
   `/config/acceptance/<run-id>/`, including original saved-file metadata.
3. Applies a combined scenario in one commit and checks native state.
4. Saves the committed configuration and retrieves backups to the controller.
5. Requests a delayed reboot and waits for a **different kernel boot ID**, active
   configd/netlinkd/FRR/nftables services, and a functioning configuration API.
6. Checks exact running/saved configuration, repeats the native assertions, and
   compares the native nftables and FRR configuration against their preboot snapshots.
7. Restores original running configuration, then the original saved file. Unsaved
   changes from before the test remain unsaved. Successful runs retain backups.

Keep the router exclusive to the suite until restoration completes. The commit
lock cannot span a reboot, so this is an exclusive lab workflow, not coordination
with simultaneous administrators. Restoration commits the original running
configuration; it does not perform a second reboot or assert every original
service's dataplane behavior.

## Comprehensive configuration

The suite installs one combined configuration with more than 300 literal `set`
commands. The fixtures are deliberately readable and reviewable:

- [Interfaces](config/interfaces.set): physical Ethernet, dummy, loopback,
  reciprocal veth pairs, Ethernet/veth/bridge VLANs, two VRFs, bridge access and
  trunk ports, STP timers/guards, VLAN 1 removal, static FDB, multicast controls,
  MTU, MAC, description, link groups, disabled links, and DHCP client options.
  Every registered interface IP/IPv6 option is explicitly exercised across those
  links, including ARP policy/timers, forwarding controls, RA/SLAAC controls,
  stable privacy, tokens, EUI-64, link-local behavior, DAD and neighbor timers.
- [Routing](config/routing.set): IPv4/IPv6 discard, gateway, interface, weighted
  multipath, preference/tag/metric, disabled and source-specific static routes;
  default and cross-VRF next hops; ACLs including inverse masks, prefix lists,
  standard/expanded community and large-community lists, AS-path lists,
  route-map matches/setters/call/next/goto; a default BGP instance with behavior
  parameters and dynamic listening, plus actual IPv4/IPv6 eBGP peers in two VRFs.
- [Services and containers](config/services.set): four Kea instances (IPv4/IPv6
  in the default VRF and BOOTLEFT), disjoint pools, IPv4/IPv6 reservations,
  inherited/overridden options and lifetimes, default-VRF hostfile hook recovery;
  registries, dual-stack and VRF container networks, static attachments/IDs/aliases,
  a shared dual-stack pod with two members, resource limits,
  entrypoint/arguments, hostname, capability, device, DNS, environment file and
  override, persistent bind mount, tmpfs, and a published port.
  VRF-bound Chrony covers server/pool sources, NTS, preference, IPv4/IPv6 listeners
  and client ACLs without depending on reachable upstream time servers.
- [Firewall and NAT](config/firewall.set): both families' input/output/forward
  filters and raw hooks; state policy, global and rule flow enrollment; nested
  jumps; address/interface/MAC/port/ICMP groups; maps and concatenated match
  groups; dynamic learners; positive/negative matches; TCP flags/MSS, packet
  length/TTL/DSCP/marks, ICMP, connection metadata/original/reply/accounting;
  packet/byte/per-key/subnet limits, connection limits, shared counters/quotas,
  logging, NFLOG collectors, nested singleton inclusions, native interface prefixes
  in rules/groups/zones/flowtables, FIB, link-group and VRF-aware matches, reject
  responses, disabled rules, zones/intra-zone/local policies, NAT maps and masquerade.
  Recent coverage includes inet rules and providers, IPv4/IPv6/inet ingress,
  VLAN keys, future device subscriptions, flowtable accounting, map default
  results, source validation, FTP/TFTP/SIP helper assignment, TCP/UDP timeout
  policies, tracing, mark/DSCP/TTL/MSS modification and automatic VRF conntrack zones.
- [Image and operational metadata](checks.py): the running kernel and installed
  kernel package must match the image lock; version/license, package inventory and
  configuration script priorities must execute through the public operational API.
- [File logging](config/services.set): global severity/rotation and a per-service
  override, fresh service and container messages, and separate IPv4/IPv6 NFLOG
  packets with scoped rule output. Checks require newly appended records, so logs
  retained from before the reboot cannot hide a collector that failed to restart.

The native checks are individually named in [checks.py](checks.py) and
[feature_checks.py](feature_checks.py), with separate
IPv4/IPv6 observations. BGP must establish and install received routes with the
expected policy attributes. A DHCP client on `br994` must acquire its reservation
from BOOTLEFT's Kea instance and install a default route with AD 210. VLAN traffic
must cross the veth pair. IPv4 and IPv6 packets must populate dynamic address
groups. Flowtable hooks must attach exactly once to both recreated forwarding
interfaces selected by prefixes. Nested group members and prefix selectors must
remain installed. The container must run and read its original persistent sentinel
through the bind mount, with the expected environment and native settings.

The suite also checks every active named-chain rule in order and every map/set
provider, then compares the **complete native nVyR nftables table and FRR running
configuration** across reboot. Handles, counters, last-used timestamps and learned
members are runtime state and excluded; expressions, rule order, configured
elements, object definitions and routing commands remain compared. FRR's
per-daemon startup hostname metadata is excluded from the policy comparison;
the OS hostname is checked directly against the configured value or default.
Complete
before/after snapshots and bounded differences are retained for investigation.
The separate VRF conntrack table is also compared. Allocated numeric zone IDs may
change after reboot; snapshots compare the VRF owning each interface instead.
Moving an interface to the wrong zone still fails the comparison.

This is broad configuration-recovery coverage, not every possible combination or
a replacement for the feature smoketests. For example, NAT/flowtable definitions
are checked here, but their full traffic matrices remain in the firewall
[functional tests](../functionaltests/README.md). GeoIP and domain-group DNS downloads/refresh, DHCP lease-to-hostname event
publication (beyond hook/timer recovery), alternate mutually exclusive modes, all
negative verification cases and external hardware interoperability are not
claimed as reboot coverage. Management accounts, SSH and management addressing
are preserved rather than replaced with test credentials.

The [coverage checklist](coverage.md) ties recent additions to their configuration,
native observations and any qualification blockers. Keep it current when extending
these fixtures. The local comprehensive test requires an explicit fixture value for
every registered interface IP/IPv6 option and every named TCP/UDP timeout state.

## Lab prerequisites

- An exclusive disposable router with no existing firewall, NAT, routing-policy,
  routing-protocol, container, VRF, or DHCP-server configuration. Management
  Ethernet, login, SSH and ordinary system configuration can remain.
  Existing NTP configuration is backed up, replaced by the lab's VRF-bound instance,
  and restored after success.
- An explicitly selected spare physical Ethernet port, without addresses,
  consumers or routes. Without carrier, the physical IPv6/VLAN address check is
  reported as **SKIPPED** with a reason before and after reboot, allowing the run
  to continue. Physical link configuration, IPv4 addresses, VLAN definitions and
  the virtual-network checks still run. Provide carrier to exercise IPv6 address
  readiness too; an isolated virtual switch in a VM lab is sufficient. The suite
  never chooses a port automatically or uses a veth in place of physical Ethernet.
- A **preloaded Alpine-compatible image** providing `sleep`, `hostname`, `cat`,
  `env`, and `test`. The default name is `alpine`; image inspection is mandatory
  and the suite does not download an image. The workload uses a 128 MiB limit.
- The router's normal current FRR, Kea, Podman/Netavark and nftables packages and
  pinned kernel (including native flowtable prefix support). Packet tests bind loopback UDP port 53098; container port
  publication uses 127.0.0.1:41995.

Reserved resources include BOOTLEFT/BOOTRIGHT, VRF tables 41995/41996,
`dum992`, `dum995` through `dum999`, `veth993`, `veth994`, `veth995`, `veth997`, `br994`, `br995`,
VLAN 195 on the selected Ethernet/veth/bridge parents, BOOTBOX/BOOTNET/BOOTVRF,
IPv4 `198.18.192.0/19`, and IPv6 `2001:db8:192::/64` through `2001:db8:210::/64`
(the third hextets are the literal strings shown). Preflight rejects collisions.

Persistent workload inputs are created under `/config/containers/boot-<run-id>/`.
Those files and acceptance backups remain after restoration for inspection;
remove the specific run directories when no longer needed. Verification never
recreates the sentinel, so missing persistent storage cannot produce a false pass.

## Failures and recovery

A failure leaves the test configuration installed for inspection; it does not
hide a failed boot by immediately restoring. `result.json` identifies the failing
phase. Diagnostics include named check results, current-boot service logs, link
and route inventories, nftables JSON, FRR configuration, and the configuration
backups. If the host cannot be reached, the controller records that failure and
retains its pre-reboot diagnostics/backups. Use the VM console to investigate.

```sh
python -m acceptance.runner diagnostics nvyr-lab --run-id <UUID>
python -m acceptance.runner verify nvyr-lab --run-id <UUID>

python -m acceptance.runner restore nvyr-lab --run-id <UUID> --disposable
```

An explicit restore replaces current running/saved configuration with the
original backups. Do not use it after making changes you want to retain.
If configd cannot start, repair the boot problem through the VM console before
invoking restore. The `original.json` record also contains the original saved
file as base64 (`saved_bytes`, or null if absent), for manual recovery.

Artifacts contain configuration secrets, password hashes, and possibly other
credentials. Unix artifacts/directories use restrictive permissions. On Windows,
choose an artifact directory with a private ACL. Do not publish them unredacted.
Remove retained artifacts/backups manually when no longer needed.

## Development checks

```sh
python -m pytest tests/test_boot_acceptance.py tests/test_comprehensive_acceptance.py tests/test_acceptance_preflight.py tests/test_acceptance_snapshots.py
```

These tests exercise the complete CLI fixture through real validation/generation,
saved-config startup replay, restoration, input checks, controller/agent failure
handling and native-snapshot comparison. Native application boundaries are
substituted, so they never reboot or configure the developer machine. Only an
explicitly invoked external `run` establishes real boot recovery.
