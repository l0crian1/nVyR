# Live configuration smoketests

Smoketests validate **nVyR CLI configuration → installed native configuration**.
They commit through `ConfigurationSession`, inspect the destination, and check
that invalid configuration is rejected without changing running or native state.

Examples include FRR running configuration, nftables rules and objects, kernel
link/address settings, sysctl values, Kea configuration, Chrony directives,
and Podman inspection data. Expected values are independent of nVyR's renderer.

Smoketests do not wait for BGP sessions or route exchange, send packets to prove
firewall verdicts, acquire DHCP leases, test container workloads, or exercise
operational commands. Those checks are preserved in
[functionaltests](../functionaltests/README.md).

## Running

Run on a dedicated nVyR test router as root:

```bash
sudo python3 -m pytest -v -s /usr/lib/nvyr/smoketests/
```

Include Ethernet and container configuration coverage with an explicitly selected
spare physical port and a preloaded BusyBox-compatible image:

```bash
sudo python3 -m pytest -v -s /usr/lib/nvyr/smoketests/ --ethernet-interface eth1 --container-image alpine
```

These selections never choose a management port or download an image automatically.
An unplugged spare port can satisfy address-configuration checks: an installed IPv6
prefix is sufficient even while duplicate-address detection is pending.

Run a feature, one case, or report the slowest stages:

```bash
sudo python3 /usr/lib/nvyr/smoketests/test_bgp.py

sudo python3 -m pytest -v -s /usr/lib/nvyr/smoketests/test_firewall.py -k ipv6

sudo python3 -m pytest -v -s /usr/lib/nvyr/smoketests/ --durations=20
```

## Isolation and restoration

Both live suites share the session, backup, assertions and resource helpers in
this directory. They run sequentially; pytest-xdist is not supported. Each case
cleans up its own changes. The full original running configuration is restored
at session end, including after test failures. No test saves the configuration.
Failed restoration stops the run and retains recovery information.

Firewall cases temporarily remove the router's firewall and NAT configuration.
Static routing cases remove default-VRF static routes. Management access must
not depend on those policies or routes. The suites reserve test interface names,
VRF tables and policy names, and reject existing use instead of taking ownership.

Interface fixtures reuse a created interface between cases, clearing its settings
without recreating it unnecessarily. Ethernet tests require `--ethernet-interface`
and retain both test VRFs alongside that port until the module finishes. Membership
tests attach, move and detach the port without replacing those routing domains.
Other interface types use disposable configured links.

Firewall modules retain their dummy interfaces and, when needed, a VRF or ingress
veth pair. Each case clears firewall/NAT rules and restores changed link attributes
without deleting the supporting devices. Explicit device-recreation checks still
perform their own delete/commit/create sequence.

Static routing retains its next-hop interface and optional VRF, withdrawing test
routes between cases. DHCP retains its private interfaces/VRFs. NTP, DHCP hostfile,
loopback and logging modules install their baseline once and reset case-specific
settings afterward, rather than restoring the original configuration between cases.

BGP fixtures retain their VRF, base policy and supporting dummy interface for the
module. Each case restores its baseline configuration in one commit; rejected
candidates only need to be discarded. Peer establishment is never awaited.

Container tests reserve names and inspect the preloaded image once per module.
Compatible container-option cases share a network definition, while network
mutation cases use their own networks. Test workloads handle SIGTERM so normal
cleanup does not wait for Podman's forced-stop timeout. Containers are still
replaced when the feature under test requires different creation settings.

The VRF lifecycle suite intentionally starts with absent VRFs: its cases verify
creation, deletion, table changes and rejection without leaving devices behind.
Policy tests have no supporting topology to retain and already commit cleanup only
when installed policy objects changed. Keep such incompatible lifecycle checks
separate instead of weakening their starting-state assertions for fixture reuse.

## Coverage boundary

- **Routing:** installed FRR static-route directives, BGP instances/neighbors/parameters,
  policy definitions and references; no Established-state or convergence wait.
- **Firewall/NAT:** native rules, groups, maps, concatenations, hook restrictions,
  defaults, modifications, reference protection, lifecycle and verification.
  Native rule assertions identify the exact rule comment and use `nft -s`.
- **Interfaces:** creation/deletion, attributes, VLANs, bridges, VRFs, addresses,
  and inherited kernel settings; no connectivity or carrier requirement.
- **Services and containers:** translated options and native configuration,
  replacement/removal and validation; no requirement for a responding peer.

Configuration application still starts services where that is the normal product
behavior. A smoke test observes their configured state; it does not separately
prove their protocol, process recovery or packet-processing behavior.

Known native configuration/listing limitations remain tracked in
[upstream issues](../docs/dev/upstream-issues.md). Moving a behavior check does not
suppress its failure: run the functional suite to exercise it.

## Adding tests

Write a directly named function for each feature, with separate IPv4 and IPv6
functions. Keep setup, commit and native assertions visibly separated. Include
verification failures and confirm that rejected candidates preserve running state.

If a scenario needs traffic, convergence, lease acquisition, process failure or
operational execution, add it to `functionaltests/` instead. When a feature needs
both kinds of coverage, keep a focused native-configuration case here and its
end-to-end behavior case there. Reuse fixtures rather than importing test functions.
