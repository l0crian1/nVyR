# Live functional tests

This suite checks behavior after configuration: packets, protocol exchange,
process lifecycle, workload execution and operational commands. It is separate
from [configuration smoketests](../smoketests/README.md), which check how nVyR's
CLI configures the destination process or kernel.

Compatible features share complete network scenarios. Setup, native object
creation and protocol convergence happen once per scenario, while each behavior
still has its own named test. Mutation and recovery cases use separate scenarios
when they would disrupt that baseline.

## Running

On a dedicated nVyR test router:

```bash
sudo python3 -m pytest -v -s /usr/lib/nvyr/functionaltests/ --ethernet-interface eth1 --container-image alpine
```

For Ethernet lease acquisition, renewal, default-route distance and DHCP MTU
behavior, connect the spare port to a test DHCP server and add `--ethernet-dhcp`:

```bash
sudo python3 -m pytest -v -s /usr/lib/nvyr/functionaltests/interfaces/test_ethernet.py --ethernet-interface eth1 --ethernet-dhcp
```

Run the integrated BGP, static routing and firewall scenario:

```bash
sudo python3 -m pytest -v -s /usr/lib/nvyr/functionaltests/network/ --durations=20
```

Run deliberate BGP policy replacement or ingress packet matching separately:

```bash
sudo python3 /usr/lib/nvyr/functionaltests/network/test_bgp_policy.py

sudo python3 -m pytest -v -s /usr/lib/nvyr/functionaltests/network/test_firewall_ingress.py
```

Run DHCP HA allocation, replication and failover checks:

```bash
sudo python3 -m pytest -v -s /usr/lib/nvyr/functionaltests/test_dhcp_ha.py
```

One isolated network fabric is retained for IPv4/IPv6 active-active and
active-passive peers. The partner-failure case uses Kea's normal failure timers,
so this functional suite intentionally includes a detection wait. It leaves the
host's configured DHCP servers and management interfaces alone.

A single case can be selected with `-k` or `file.py::test_name`. Use
`--durations=20` to see where setup, execution and cleanup spend their time.
The ordinary repository test command still discovers only `tests/`.

Ethernet IPv6 address-readiness tests require carrier on the selected spare port.
Without a cable or loopback adapter they explicitly skip, rather than timing out
waiting for addresses Linux cannot make ready. The configuration smoketests still
validate the requested addresses without requiring physical carrier. Both Ethernet
suites retain the physical interface between cases. Functional Ethernet borrows
the interface package's VRFs; resets clear port settings without deleting them.
An explicitly selected empty Ethernet profile is accepted and restored afterward.
A nonempty profile, external reference, master or non-link-local route/address
still prevents borrowing the port.

Account lifecycle testing uses a separate, fresh disposable systemd image. Stop
configd and use an image with no existing `/var/lib/nvyr/state.json`; this suite
creates accounts and its own SSH listener. Run it from a developer console:

```bash
sudo env NVYR_LOGIN_TEST=1 python3 -m pytest -v -s /usr/lib/nvyr/functionaltests/test_cli_login.py
```

It covers authentication, isolated CLI roles, developer host access, role
revocation and configd restart. It is skipped during ordinary functional runs.

## Shared scenarios

The subdirectories are pytest packages with **package-scoped** topology ownership.
Running several files in one package creates its complete configuration once.
Selecting one file or test still prepares that same baseline; no test depends on
another test having run first. Test functions remain explicit and separately named.

### Routed network

Every script under [network/](network) uses the same VRFs, interfaces and BGP
sessions. The baseline is split into readable literal configurations:

- [routed-network.conf](configs/routed-network.conf): dual-stack BGP, static
  forwarding, policy attributes and packet tests across two simulated LANs.
- [network-features.conf](configs/network-features.conf): independent firewall
  rules, groups, maps, ingress selectors, limits, quotas and policy-view objects.
- [network-policies.conf](configs/network-policies.conf): dedicated prefixes and
  route-map clauses for mutable community/AS-path tests, plus BGP operational views.
- [network-bgp-unicast.conf](configs/network-bgp-unicast.conf): capabilities, roles,
  limits, weight/distance, aggregates and conditional advertisements on the shared
  peers, plus one persistent unnumbered link for alternate-AS exchange. IPv4 and
  IPv6 filter/condition changes reuse these sessions and restore the baseline.
- [network-static.conf](configs/network-static.conf): distinct static destinations
  for FIB installation, preference, ECMP and withdrawal tests.
- [network-services.conf](configs/network-services.conf): DHCPv4/v6, NTP, logging
  and the default-VRF links used by global flowtable tests.

BGP convergence and initial end-of-RIB are checked once. Policy changes and hard
peer resets still wait for their intended withdrawal or reconvergence. Ordinary
show commands and packet observations do not commit. Mutation cases restore only
configuration differences; topology remains instantiated.

Dedicated ports, prefixes, rule numbers and objects prevent competing cases from
consuming each other's state. The routed forwarding scenario uses counter deltas
and fresh sockets. Per-case local probes have their own counters and allowance
objects. Scoped offload cannot bypass another feature's rules.

Global/default firewall tests use `exclusive_firewall`: each case installs its
own policy, while the large common firewall is restored once at module exit.
All links, VRFs and routes stay alive. This applies to source-validation modes,
zone ownership, and inet/family default verdicts. The global flowtable module shares one temporary policy across
its cases. Static last-route/empty-instance tests use `exclusive_static` for the
same reason. These are deliberate policy transitions, not topology recreation.

### Interfaces

Every script under [interfaces/](interfaces) shares
[interfaces.conf](configs/interfaces.conf). Dummy, veth, bridge, VIF and VRF cases
have dedicated links and subnets, but all reuse the same two routing domains.
Compatible addresses, VLAN memberships and forwarding topologies are installed
in one transaction. Completed changes to private links remain until final cleanup;
there is no redundant per-case restoration commit. Loopback cases own separate
address values or the alias. Only the explicit VRF create/delete test creates
disposable additional VRFs. Ethernet options are reset between incompatible
physical-port cases without deleting the port or its shared VRFs.

### Containers and pods

Both scripts under [workloads/](workloads) share a single installation of
[containers.conf](configs/containers.conf) and [pods.conf](configs/pods.conf):
26 standalone workloads, four pods and six pod members. Image inspection,
configuration commit and final cleanup happen once for the package. Each mutation
owns its workload, pod or network, so it cannot restart another case's container.

The idle workload handles SIGTERM, avoiding a forced-stop timeout for a bare
`sleep` as PID 1. Pod localhost probes exchange TCP traffic through member network
namespaces without requiring an HTTP server in the image.

### Native operational and isolated lifecycle tests

The remaining scripts were reviewed individually:

- `test_conntrack.py`: all NAT modes, IPv4/IPv6, ICMP and zone/accounting records
  coexist in one module-lived namespace. Queries select distinct original
  addresses. The label case sends its own isolated packet.
- `test_nat_operations.py`: source rules, destination rules and a map are installed
  together once. The empty-view case uses a separate empty namespace.
- `test_neighbor_dns.py`: both neighbor families, default/VRF scope and one DNS
  responder persist for the module. Positive and negative queries need no reset.
- `test_interface_operations.py`: read-only diagnostics reuse one physical-port
  selection; they create no links or configuration.
- `test_system_operations.py`: read-only system reports create no network state.
- `test_firewall_failsafe.py`: each case tests a separate boot/handover/failure
  lifecycle in an isolated namespace. Reusing an already-activated table would
  invalidate the startup precondition. These cases do not touch configd's network.
- `test_frr_scripting.py`: one isolated FRR pathspace tests the installed Lua hook.
  Its custom daemon startup cannot share the managed routing daemons.
- `test_cli_login.py`: an opt-in disposable image tests account creation, login,
  revocation and configd restart. It cannot run against the shared live session.

Module headers explain coverage and incompatible state. New compatible behavior
belongs in the existing package baseline, regardless of its subsystem. Keep
lifecycle transitions explicit rather than rebuilding the topology as a side
effect of a function-scoped fixture.

## Preserved coverage

- Static-route kernel installation/withdrawal, preference and multipath selection.
- IPv4/IPv6 BGP route exchange, community and AS-path policies, policy changes,
  received/advertised routes, soft refresh, hard resets and reconvergence.
- Firewall verdicts, nested jumps, inet dispatch, ingress VLANs, wildcard matches,
  source validation, dynamic learning, shared limits/quotas and zone counters.
- VRF output bypass and second-pass policy enforcement, flowtable enrollment,
  timed packet tracing, and early fail-safe firewall handover/failure behavior.
- Bridge forwarding, learning, VLAN separation, port isolation and learned-MAC
  cleanup; veth/VIF connectivity across routing instances.
- DHCP process start/stop, lease release/renewal, route preference and MTU behavior;
  Chrony client access and serving activity; logging and FRR Lua callbacks.
- Container commands, DNS aliases, mounts, shared pod localhost, process restart,
  workload preservation and operational views.
- Installed operational commands for routing/policies, interfaces, users,
  system diagnostics, neighbors, DNS, NAT and conntrack.

## Test environment

Both live suites ship in the nVyR package and share the helpers in `smoketests/`.
Do not copy only this directory to a router. Shared fixtures preserve the original
running configuration and restore the original tree at session end. Shared
packages clean up once at package exit; native operational fixtures clean up at
module exit. Deliberately isolated lifecycle cases clean up their own resources.
No test saves the configuration. Cleanup failures stop subsequent tests.

Use a dedicated test router. Firewall cases temporarily remove firewall/NAT;
static cases remove default-VRF static routes. Management must not depend on them.
Never select the management interface as the spare Ethernet port. Existing test
names and table IDs cause preflight failure instead of being reused.

Owned resource names, table IDs and subnets are listed in the configuration files.
The network package reserves NVYRLEFT/NVYRRIGHT (42061/42062), NVYRSMOKE (41001),
NVYRFWSMOKE (41002), NVYRDHCPSMOKE (41980), NTPTEST (41977), their listed links and
four simulated-host namespaces. The interface package reserves NVYRIFSMOKE and
NVYRIFSMOKE2 (41010/41011), with IFDELETE1/IFDELETE2 (41990/41991) reserved for the
explicit lifecycle test. Setup rejects existing names, native devices and Podman
objects rather than silently adopting them.

Packet tests keep their address-readiness checks. Ethernet lease tests need a
server and carrier; ordinary veth/namespace packet tests create their own peers.
Containers require a preloaded BusyBox-compatible image. DNS protocol tests use a
local responder without depending on public DNS. Domain-group refresh tests need
working public DNS; GeoIP refresh tests need DB-IP HTTPS access. The FRR scripting
test launches separate daemons in an isolated namespace and FRR pathspace.

Run sequentially, without pytest-xdist. Acceptance remains a separate suite for
combined saved configuration and reboot restoration; see
[acceptance testing](../acceptance/README.md).
