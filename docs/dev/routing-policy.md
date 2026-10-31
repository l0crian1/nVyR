# Routing policies: implementation and maintenance

For configuration and command usage, see the [user guide](../users/routing-policy.md).

## FRR integration and recovery

The supported baseline is FRR 10.7.1. Policies use the shared
[`frr_reload.Manager`](../../src/nvyr/helpers/frr_reload.py), alongside static routing.
`generate()` renders the native list and route-map structure through
`frr/policy.conf.j2`, using Python helpers for normalized operands and match/set
expressions. The policy adapter replaces only the named access lists, prefix-lists, AS-path lists,
community lists and route-maps owned
by nVyR in a complete integrated running snapshot. `frr-reload.py` computes and
applies the delta through vtysh to the appropriate daemons, including BGP setters.
Both zebra and bgpd must be available. bgpd uses ordinary CLI mode without `--tcli`.

Our `frr-pythontools` package builds a narrowly patched FRR reload script at
`/usr/lib/frr/frr-reload.py`. It removes old BGP list entries before replacements,
fixing same-sequence AS-path changes and standard/expanded community-list changes.
See [source and patch provenance](../../vendor/frr/README.md).

Reload is **not atomic**. The manager records scopes and a before-image before
applying, verifies the native running configuration afterward, and restores the
previous policy configuration on failure. Unconfirmed restoration raises
`RecoveryError` and blocks further commits. Configd recovery uses its authoritative
configuration and durable scope claims to remove unpublished objects after an
interruption. The shared reload lock serializes static and policy updates.

The adapter preserves unrelated policies, static routes, and other FRR settings.
Unchanged policies do not reload. Deletion removes the claimed native policy
objects. Reloads do not write `/etc/frr/frr.conf`; nVyR's saved configuration
remains the boot source. See [FRR integration](frr.md) for the shared contract.

Use a rebuilt image for this pipeline. A development installation previously
configured with `bgpd --tcli` must have that flag removed from `/etc/frr/daemons`
and FRR restarted before using the ordinary CLI reload path. The package no longer
adds transactional mode and does not restart routing daemons during installation.

## Tests

Live router tests are installed with the image:

```sh
sudo python3 /usr/lib/nvyr/smoketests/test_policy.py
```

The suite uses reserved names, cleans up between functions, and participates in
the shared full-run snapshot/restore. It covers both families, inverse masks,
references, setters, and verification failures. The integrated
`functionaltests/network/test_routed_network.py` scenario checks actual IPv4/IPv6 eBGP
exchange, community filtering/deletion, AS-path replacement, ACLs, prefix lists,
calls and attribute adjustments on the same topology as static forwarding and
firewall packet tests. Its configuration is installed once for the whole module.
The separate `test_bgp_policy.py` cases exercise route withdrawal following list
updates; `test_bgp_operational_peers.py` exercises deliberate peer resets.

`tests/test_policy_live.py` additionally exercises native failure handling in an
isolated container, including partial apply, command rejection, a lost successful
reload reply, interrupted recovery, last-object deletion, and unchanged reapply.
Enable with `NVYR_POLICY_TEST=1` only after starting disposable zebra, mgmtd,
staticd and bgpd in ordinary CLI mode and installing our built FRR packages.
The live examples also run through the real
configuration engine in `tests/test_policy_smoketest.py` with that environment flag.

Sources: [FRR filtering](https://docs.frrouting.org/en/stable-10.7/filter.html),
[route-maps](https://docs.frrouting.org/en/stable-10.7/routemap.html), and
[frr-reload.py](https://docs.frrouting.org/en/stable-10.7/frr-reload.html).

Run the BGP policy exchange checks on a live router with:

```sh
sudo python3 /usr/lib/nvyr/functionaltests/network/test_bgp_policy.py

sudo python3 /usr/lib/nvyr/functionaltests/network/test_routed_network.py
```

For isolated development runs, start `nvyr-netlinkd` and FRR, then set
`NVYR_BGP_POLICY_TEST=1` when running `tests/test_bgp_policy_smoketest.py`.
Without that flag, the same examples validate CLI and lifecycle behavior without
creating network devices or BGP sessions.
