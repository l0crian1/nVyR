# Operational completion checklist

Use this checklist when adding or changing an operational feature. Extend the
existing focused tests; a new framework or a rewrite of working tests is not
required. Mark an item inapplicable when the command has no corresponding scope
or behavior, rather than inventing a test for it.

- [ ] **Dispatch:** Resolve complete commands, supported options and positional
  arguments through `Controller.execute()`, including configuration-mode `run`.
  Assert the executable and arguments, not just that execution returned text.
- [ ] **Permissions:** Read-only views work for operators. Runtime changes
  require the intended role and denied commands do not invoke their backend.
  Streaming actions are checked again when attaching the privileged terminal.
- [ ] **Installed execution:** Exercise the installed `.nvyr.op` entry point and
  its native backend in a router functional test. Calling a Python function directly
  does not verify packaging, executable permissions, imports or serialization.
- [ ] **Empty and failed states:** Distinguish an empty inventory from an
  unavailable daemon, missing selected object, unreadable state or failed native
  command. Do not accept an empty success message after a backend failure.
- [ ] **Scope isolation:** Where supported, select IPv4 and IPv6 independently,
  and test default and named VRFs. Include competing objects with the same names
  or identifiers so leaking another scope cannot accidentally pass the test.
- [ ] **Output contract:** Check the default table, scoped/detail views and raw
  JSON where implemented. Keep unknown values distinct from zero; preserve
  integer counters. Invoke `opmode.run()` when checking serialized output.
- [ ] **Mutation boundaries:** For reset/release/clear/restart commands, verify
  the selected target, preserved unrelated state, failure reporting, and any
  confirmation or cancellation behavior.
- [ ] **Execution evidence:** Record what passed locally, what ran against native
  Linux tools, and what ran on an installed router. Test collection and `--help`
  execution do not establish that a live feature works.

Keep live test functions explicit and feature-specific, with separate IPv4 and
IPv6 functions. Share assertion and setup mechanics rather than iterating a
large feature table inside a single live test.

Compatible functional checks should share one complete scenario across routing,
firewall and other subsystems. Document its coverage and incompatible mutations
in the module's opening docstring. Use package-scoped setup across compatible scripts, distinct
traffic selectors and counter deltas so cases remain independently selectable.
See the [integrated routed-network scenario](../../functionaltests/README.md#routed-network).

## Shared regression coverage

[test_operational_checklist.py](../../tests/test_operational_checklist.py) checks
every real operational script through its relocated installed symlink, using
`--help` to import the implementation without running administrative actions.
It also checks the inherited access policy of every executable command in the
actual schema, and dispatch/terminal authorization for representative runtime
changes. An unknown top-level verb requires an explicit access expectation.

[test_operational_build.py](../../tests/test_operational_build.py) and
[test_operational_sources.py](../../tests/test_operational_sources.py) check YAML
function/argument mappings and executable installation.
[test_opmode.py](../../tests/test_opmode.py) and
[test_operational_access.py](../../tests/test_operational_access.py) cover shared
dispatch, role inheritance and anchored options.
[test_privileged_operations.py](../../tests/test_privileged_operations.py) covers
real peer credentials, streaming, interruption and reconnection.

## Coverage index

The files below are the feature-specific evidence to extend. Their presence is
not a claim that every selector or every hardware backend has been run on a
live router in the current checkout.

- **Users, service health and system reports:**
  `tests/test_service_health_op.py`, `tests/test_system_op.py`,
  `tests/test_diagnostics.py`, `tests/test_system_native.py`;
  `functionaltests/test_system_operations.py`.
  Service tests include stopped, failed, missing and not-ready instances.
- **Interfaces, bridges and VRFs:** `tests/test_interfaces_opmode.py`,
  `tests/test_bridge_operations.py`, `tests/test_system_op.py`,
  `tests/test_ethtool.py`, `tests/test_interface_diagnostics_live.py`;
  `functionaltests/test_interface_operations.py`, `functionaltests/interfaces/test_bridge.py`,
  `functionaltests/interfaces/test_vrf.py`. Unsupported hardware capabilities remain visible;
  physical Ethernet and transceiver evidence requires suitable hardware.
- **DHCP clients and servers:** `tests/test_dhcp_op.py`,
  `tests/test_dhcp_views.py`, `tests/test_dhcp_options_live.py`;
  `functionaltests/network/test_dhcp_server.py`, `functionaltests/interfaces/test_ethernet.py`.
  Journal tests reuse pool names and subnet IDs across both families and VRFs,
  and distinguish a failed instance from an empty lease database.
- **NTP:** `tests/test_ntp.py`, `tests/test_ntp_operations.py`,
  `tests/test_ntp_native.py`; `functionaltests/network/test_ntp.py`.
  NTP has one managed instance, optionally bound to a VRF; its reports select
  that instance's control socket, not separate per-VRF daemons.
- **Containers:** `tests/test_container_operations.py`;
  `functionaltests/workloads/test_container.py`. Coverage includes exited containers, failures
  before creation, scoped networks/images/statistics, and restart restrictions.
- **Firewall and runtime state:** `tests/test_firewall_opmode.py`,
  `tests/test_firewall_runtime_views.py`, `tests/test_firewall_runtime.py`,
  `tests/test_geoip.py`; `functionaltests/network/test_firewall.py`,
  `functionaltests/network/test_firewall_allowances.py`, `functionaltests/network/test_firewall_runtime.py`,
  `functionaltests/network/test_firewall_geoip.py`. Native runtime view tests are in
  `tests/test_firewall_runtime_views_live.py`.
- **NAT and conntrack:** `tests/test_nat_opmode.py`,
  `tests/test_conntrack_opmode.py`; `functionaltests/test_nat_operations.py`,
  `functionaltests/test_conntrack.py`. Coverage includes source/destination/double
  translation, state/family selection, absent accounting and Netlink failures.
- **Static, BGP and policies:** `tests/test_static_op.py`,
  `tests/test_bgp_op.py`, `tests/test_policy_op.py`, `tests/test_vtysh.py`;
  `functionaltests/network/test_static.py`, `functionaltests/network/test_bgp_operations.py`,
  `functionaltests/network/test_bgp_operational_peers.py`, `functionaltests/network/test_policy_operations.py`.
  Preserve FRR word order and native empty/error responses.
- **Neighbors and DNS:** `tests/test_neighbor_dns_op.py`;
  `functionaltests/test_neighbor_dns.py`. The suite covers VRF scoping, IPv4/IPv6,
  unresolved neighbors, NXDOMAIN, empty answers and resolver failures.
- **Ping, traceroute and privileged shell commands:** `tests/test_ping.py`,
  `tests/test_traceroute.py`, `tests/test_shellcmd.py`,
  `tests/test_privileged_operations.py`. Include native status propagation and
  terminal interruption, not just argument construction.
- **Images and shutdown:** `tests/test_images.py`, `tests/test_shutdown.py`,
  `tests/test_installation_boot_live.py`, and the `acceptance/` reboot suite.
  Destructive image/boot checks belong in disposable-machine acceptance runs,
  not ordinary operational display functional tests.

## Completion pass: 2026-10-25

Added the shared installed-entry-point/access checks, competing DHCP scope
tests, backend failure checks, and bridge raw/empty/cleanup tests. Expanded live
coverage for date, uptime, CPU, memory and interface raw JSON. Existing static,
DHCP and VRF functional tests now also exercise their public configd command paths.

Two bugs exposed by checking the actual raw-output boundary were fixed:

- Bridge raw views returned Python objects, which the operational dispatcher
  rejected. They now serialize JSON.
- Interface raw output printed Python representations, which were not valid
  JSON. It now uses the same JSON return contract as the other operational views.

Validation for this pass: the main operational regression selection passed
1,033 tests; the supplementary build, assertion and DHCP selection passed 126
tests (with overlapping DHCP coverage). The final bridge fixture cleanup passed
all 10 bridge tests. Installed bridge and interface raw entry points also returned
valid JSON against native Linux tools in the disposable test container; the
bridge inventory there was empty and the interface inventory contained two links.

Remaining environment-dependent signoff is explicit: run the updated installed
functional tests on the rebuilt router; use the appropriate physical ports/transceivers
for hardware checks and a disposable VM for image/reboot acceptance. This pass
does not count those executions as completed merely because the tests exist.
