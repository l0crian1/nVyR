# FRR integration

BGP, static routing and routing policies use FRR 10.7.1's `frr-reload.py` through the shared
[`frr_reload.Manager`](../../src/nvyr/helpers/frr_reload.py). The ISO pins both `frr`
and `frr-pythontools` at `10.7.1-0~deb13u1+nvyr1`. The builder compiles both from
checksum-pinned source with FRR's `pkg.frr.lua` profile, enabling Lua scripting
while preserving the other Debian build options. Installing only the nVyR
`.deb` requires these matching FRR packages; `dpkg -i` does not fetch dependencies.

The manager uses `/usr/lib/frr/frr-reload.py` from our `frr-pythontools` build,
with the tested BGP list deletion-ordering patch applied to its source.
See [patch provenance](../../vendor/frr/README.md) for the change and regression tests.

The cached packages live in `/opt/nvyr-frr-packages` in `nvyr-image-builder`.
Rebuild that image after changing the source lock, builder recipe or patch:

```sh
docker build -t nvyr-image-builder -f images/Dockerfile .

docker run --rm --privileged -v "$PWD:/workspace" nvyr-image-builder
```

The first command compiles FRR and runs its Debian build tests; subsequent ISO
builds reuse the verified packages. `NVYR_BUILD_JOBS` controls compiler jobs when
running `build_tools/frr_packages.py` directly (default 4). Source pins and artifact
hashes are recorded under `/usr/share/nvyr/` in the ISO and the package manifest is
exported as `dist/nvyr-0.1.0-amd64.frr-packages.json`. Scripting is compiled in;
no Lua hooks are configured automatically, and no new nVyR CLI syntax is added.

`tests/test_frr_scripting_live.py`, enabled with `NVYR_FRR_SCRIPTING_TEST=1`,
starts disposable FRR processes in a separate network namespace and verifies a
Lua callback during a real route installation. Run only in a privileged test
container after installing the built packages.

Access lists, prefix-lists and route-maps use the same serialized reload and
recovery path; see [routing policies](routing-policy.md). Each adapter replaces
only its owned portion of the integrated configuration, preserving other owners.
bgpd runs in ordinary CLI mode, without `--tcli`.
Configuration and command references live in [static routing](../users/static.md),
[BGP unicast](../users/bgp.md), [routing policies](../users/routing-policy.md),
[static routing displays](../users/static-routing-operations.md), [BGP displays](../users/bgp-operations.md)
and [policy displays](../users/policy-operations.md).

## Shared reload pipeline

Config scripts keep the usual `get_config`, `verify`, `generate`, `apply` stages.
Static `generate()` passes each VRF's effective configuration directly to
`templates/frr/static.conf.j2`. The registered Python formatter in
`helpers/frr_static.py` emits native FRR commands; Jinja only joins the lines.
Descriptions remain nVyR metadata, and disabled entries produce no commands.

The shared manager handles all execution mechanics:

1. Serialize reload users with `/run/nvyr-frr/reload.lock`.
2. Read the integrated configuration with `vtysh -c 'show running-config no-header'`.
3. Record the owner's scopes and before/target state durably.
4. Let the feature adapter replace its portion of that snapshot.
5. Run `frr-reload.py --reload` on the complete resulting configuration.
6. Read back the configuration and confirm the owner's intended state.

The static adapter owns unicast `ip route` and `ipv6 route` statements in its
claimed VRFs. It preserves other VRFs, policies, interface settings, and protocol
configuration. VRF declarations are retained when their last route disappears.
FRR performs the delta calculation and command ordering; nVyR does not implement
its own per-route diff or restart routing daemons to apply configuration.

The reload input is a temporary `frr.conf` whose parent is passed as `--confdir`.
This matters: FRR 10.7.1 implicitly calls `write` for an integrated input outside
that location. The manager does not request `--overwrite`; neither normal commits
nor restoration write `/etc/frr/frr.conf`. Scratch files and logs use the writable
runtime directory and are removed after execution. Each subprocess has a bounded
execution time, and timeout cleanup terminates the reload process and its children
before attempting restoration.

Each adapter declares the daemons that must be reachable: static routing requires
`staticd` and `zebra`; policy and BGP application require `zebra` and `bgpd`. Matching
command text confirms FRR's configuration, not asynchronous protocol convergence,
neighbor resolution or kernel FIB convergence. Native tests separately inspect
installed state. Unchanged owned configuration skips the reload process.

## Ownership and failure recovery

Configd remains authoritative for the static routes, BGP instances and named
policies claimed by its adapters. Do not edit those objects independently through
vtysh. Concurrent external FRR configuration writers are not supported: the nVyR
file lock serializes its own reload users, not arbitrary administrative vtysh sessions.

Per-owner records under configd's state directory (`frr-reload/static.json`,
`frr-reload/policy.json`, and `frr-reload/bgp.json`) retain claimed VRF or policy
names and pending before/target state. Scopes are recorded before execution so newly introduced routes and policies
can be cleared after an interrupted commit, even when absent from the engine's
configuration before-image.

A reload can apply some changes before failing. On failure, the manager reads a
fresh running snapshot, restores the owner's previous state, and verifies it.
Other sections are preserved from that fresh snapshot. A verified restoration
returns an ordinary commit failure. If restoration cannot be confirmed, a
`RecoveryError` leaves the journals intact and configd blocks further writes.
Restart recovery reconciles to the engine's authoritative configuration. Recovery
failure never restores the interrupted candidate.

FRR's CLI still uses MGMTd internally for converted commands. A failed native
reload can leave its global candidate dirty even when running state is unchanged.
The shared process rejects pre-existing uncommitted changes before starting. After
an owned failure, it takes FRR's native file lock, issues `mgmt commit abort`, and
confirms candidate equals running before restoring the owner's configuration.
An interrupted reload's durable pending record permits the same cleanup during restart recovery. These
are staging checks only; no desired configuration is loaded through YANG JSON.

This is reconciliation with recovery, not a globally atomic transaction. Restoring
configuration cannot undo transient route withdrawals or protocol events.
Existing independent config-script commit boundaries remain in effect.

nVyR `save` and its boot configuration remain authoritative. Restarting
`frr.service` restarts configd through the existing `PartOf=` relationship, allowing
intent to be replayed. If FRR state is independently lost outside that service
restart, restart configd to reconcile it.

## Static adapter and VRF retention

`protocols_static.get_config()` uses the script's registered VRFs rather than
searching all VRFs. All of its routing instances are processed together. Linux
VRF creation remains owned by the interface manager.

An omitted previously claimed VRF means withdraw its static routes. Neither the
adapter nor reload target requests deletion of its protocol instance. Native
FRR CLI deletion retains empty static instances, avoiding the previously observed
staticd crash when destroying populated YANG protocol instances. An unused system
need not synthesize an empty YANG instance: the CLI creates native state when its
first route is installed. See [upstream investigations](upstream-issues.md).

## Adding another feature

Reuse `frr_reload.Manager`; do not invoke reload independently or pass a partial
file directly. A feature supplies its complete desired scope dictionary and an
adapter with two methods:

- `select(text, scopes)` returns normalized owned configuration for those scopes.
- `replace(text, desired)` returns complete integrated configuration with only
  those scopes replaced, preserving every other context.

Missing claimed scopes receive empty lists so removal and crash recovery use the
same path. Adapters must recognize exact contexts, retain meaningful order, and
compare equivalent native writer output consistently. Formatting belongs in
Python helpers registered with `template.py`, not in the process manager.

The manager takes an owner name, desired scope dictionary, state directory,
adapter, required daemon names, and recovery flag. Features that must apply
together should submit a combined adapter/desired configuration under one commit
owner. Sharing the process does not automatically combine otherwise independent
owners into a single transaction.

## Testing

The shared manager's unit tests are in `tests/test_frr_reload.py`, including
partial failure, failed restoration, process interruption, and engine restart recovery.

`NVYR_RELOAD_TEST=1 python3 -m pytest tests/test_frr_live.py` runs only inside a
disposable privileged container with FRR already running. It covers native command
round-trips, IPv4/IPv6 attributes, source-specific routes, VRFs, instance retention,
policy preservation, rejected commands, lost responses, and no implicit saving.

Feature-specific testing is documented with [static routing](static.md#testing),
[BGP](bgp.md) and [routing policies](routing-policy.md).

FRR reference: [configuration reload](https://docs.frrouting.org/en/stable-10.7/frr-reload.html).
