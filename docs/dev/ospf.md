# OSPF implementation

The OSPFv2 and OSPFv3 config scripts follow the normal four-stage lifecycle:

- `get_config()` gathers default and registered VRF process settings, interface
  ownership, and referenced routing policies.
- `verify()` checks area aliases/types, timer relationships, authentication
  modes, policy references and interface VRF membership. Scalar syntax and
  numeric bounds belong to schema validators.
- `generate()` renders `frr/ospf.conf.j2` with pure compound-command formatters
  and selects the resulting owned scopes.
- `apply()` sends those scopes to the existing FRR reload manager.

Configd does not configure FRR directly. Ordinary ospfd and ospf6d are already
managed by the appliance's FRR service. No numbered daemons are added.

## Ownership and readback

`frr_ospf.Ospf` owns its `router ospf[6] [vrf NAME]` sections and only its
`ip ospf` or `ipv6 ospf6` commands inside shared interface sections. It must
preserve interface descriptions, the other address family's commands, BGP,
static routes, and policies. Comments and blank separators are not commands.
Area-type commands precede commands requiring stub/NSSA state.
Interface headers use the Linux interface name without a VRF suffix, matching
FRR's Linux VRF backend. VRF membership is checked against interface configuration.

The adapter normalizes explicit values that FRR omits when they equal native
defaults. This is a readback equivalence, not an nVyR override of defaults.
The manager still verifies installed state and restores the prior state on failure.
For removal of a process with `max-metric router-lsa on-shutdown`, the adapter
supplies the configured drain timeout. Other changes retain immediate readback.

## Keychains and FRR packaging

Shared `policy key-chain` definitions are owned by the policy script and applied
before OSPF. Lifetime input is router-local time, matching FRR's native behavior.
The policy adapter preserves nested key IDs and normalizes lifetime whitespace.
Secrets are schema-marked for redaction.

FRR 10.7.1 package revision `nvyr2` includes the reviewed
[`keychain-reload.patch`](../../vendor/frr/keychain-reload.patch):

- Normalize the running writer's day padding to match file loading.
- Generate operand-free `no accept-lifetime` / `no send-lifetime` commands.
- Correct both native removal handlers to use their paths under `./lifetime/`.

The additional `ospf-reload.patch` corrects reset syntax and removes static
OSPFv3 neighbors and stub/NSSA area state after their dependent options. It also
limits opaque-extension readback to the default VRF, matching their native scope.
All three patches participate
in the package recipe digest. The image builder must
be rebuilt to supply the matching FRR packages. See
[patch provenance](../../vendor/frr/README.md) and [FRR integration](frr.md).

## Deferred native limitations

- Ordinary ospfd plus numbered processes would need a daemon-list lifecycle
  change. Numbered instances were explicitly deferred.
- Hidden `ospf lsa-refresh` and `ospf maxage-delay` settings do not survive native
  configuration readback. Do not confuse these with supported `refresh timer`.
- Virtual-link creation requires the native process already to be an ABR. This
  cannot be relied upon for first-commit or boot replay, so its schema is deferred.
  [Upstream PR #22979](https://github.com/FRRouting/frr/pull/22979) removes that
  check after 10.7.1; the [issue tracker](upstream-issues.md#frr-ospf-001-deferred-configuration-and-replay-limitations)
  records the commits to check and the retesting required on a future upgrade.
- Per-address plaintext key configuration fails because FRR's argument lookup
  advances past the key while finding the address. Ordinary interface plaintext,
  MD5 and keychain modes remain available.

## Verification

`tests/test_ospf.py` checks ownership, schema boundaries, validation and native
command mapping. `tests/test_policy_live.py` exercises key lifetime replacement
and removal against the built FRR packages; run it only in the opt-in disposable
container environment. `tests/test_frr_reload_ordering.py` checks patch behavior.

`smoketests/test_ospf.py` uses one VRF and dummy interface across translation
cases. It checks running configuration and rejection, without waiting for peers.

`functionaltests/configs/network-ospf.conf` adds both authenticated families to
the existing routed-network transit and VRFs. Dedicated destinations prevent
OSPF from hiding BGP policy failures. The tests observe adjacency, forwarding,
redistribution and deliberate policy withdrawal. Only incompatible changes
require a case reset; links and VRFs remain instantiated.

`acceptance/config/ospf.set` adds dual-stack routing and timed keychains to the
combined preboot/postboot configuration, with the default instance peering with
BOOTLEFT. Both sides require authenticated adjacency, OSPF-only routes, working
traffic and operational commands after recovery. BGP export filters exclude the
OSPF destinations so another protocol cannot mask failed OSPF route installation.
