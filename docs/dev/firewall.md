# Firewall configuration: implementation and maintenance

For configuration and command usage, see the [user guide](../users/firewall.md).

## Implementation overview

The firewall owner uses the normal get_config/verify/generate/apply lifecycle. Its
Jinja2 template reads the shared effective configuration directly. It renders native
nftables syntax through `nft_rule()` and the common keymap in `helpers/nftables_formatters.py`.
`helpers/nftables.py` checks and applies the generated file. Rendering trusts the
CLI schema for individual values/paths and `verify()` for cross-field requirements;
helpers only format expressions and preserve deterministic ordering. nftables
normalizes address and port sets.
Its schema priority is 15, after interface owners at 10, during commits and recovery.
Flowtable devices do not need to exist when the firewall loads. Firewall and NAT
share one commit owner; other owners retain their independent commit behavior.

Optional [fail-safe protection](firewall-failsafe.md) uses the shared firewall tree
at `firewall fail-safe`. Its separate owner runs before interface configuration;
the main firewall removes its temporary table atomically when it loads.

[Router initialization](initialization.md) resets the entire nftables ruleset at boot
and creates the empty `inet nvyr_filter` table. It creates no chains. Normal firewall
commits own only their managed chains and do not perform this global reset.
[IPv4 NAT](nat.md) uses separate managed entry/family chains in the same
`inet nvyr_filter` table. Affected filtering, NAT, maps, and match-groups are replaced together atomically.

## Native chains and dispatch

nVyR manages one `inet nvyr_filter` table and these reserved chain names:

- Base chains: `input`, `forward`, `output`, `prerouting`, `output_raw`.
- Family chains: `ipv4_input`, `ipv4_forward`, `ipv4_output`, and their `ipv6_` equivalents.
- Raw chains: `ipv4_prerouting`, `ipv6_prerouting`, `ipv4_output_raw`, `ipv6_output_raw`.
- Named chains: the reserved `ipv4_name_` and `ipv6_name_` namespaces.

A family chain exists only if its `firewall <family> <hook> filter` or `raw` path exists.
An empty stage is sufficient; its direct default action is `accept`. Merely setting
a firewall description, family, hook or global policy does not create a chain.
A base chain exists only when at least one family chain exists for that hook and stage.
Unconfigured families fall through its `accept` policy.

Each active filter base chain evaluates one `ct state vmap`, if configured, before a
`meta nfproto vmap` dispatches to the existing family chains. Global policies therefore
precede family rules and affect both families on active hooks. Each configured map
element has its own counter, for example `established counter : accept`.
The family dispatch is constructed by `nft_family_dispatch(firewall, hook)` in the
shared template helpers.
The state-policy expression comes from `nft_state_policy(policies)` and is not emitted
in either raw base chain.

## Rule rendering

Family rules sort numerically by rule number. The keymap orders matches before
statements, then the verdict and final comment. Multi-value nodes use sets,
including single values, except an explicitly masked address uses a bitwise
comparison. For example:

```nft
ct state { established, related } ip saddr { 1.1.1.1 } ip daddr { 2.2.2.2 } meta l4proto { tcp, udp } th dport { 22, 23 } counter last accept comment "10|Allow SSH"
counter drop comment "default|default-action drop"
```

## Firewall execution boundary

`show firewall` displays `nft list table inet nvyr_filter`; use `run show firewall`
from configuration mode. The command executes in root-owned configd through the
existing operational argv mechanism, so the CLI user does not need `sudo`. The image
also includes `conntrack` for connection-tracking inspection and `jq` for JSON processing.

## Kernel settings defaults

The early router baseline and CLI defaults use the same keymap. Detailed tunables
are applied by the firewall helper during startup, even without a firewall
configuration; they are not duplicated in the boot sysctl file.

## VRF reference reapplication

Interface VRF changes automatically reapply direct inbound-interface consumers
through the schema's `reapply-on-change: [vrf]` declaration. Changing the group
flag uses the existing group-reference lifecycle. Matching a numeric link group
does not require a rebuild when a device changes its group: nftables reads that
attribute on each packet. On INPUT, `iifgroup` is the VRF master's group, while
PREROUTING sees the member's group; there is no slave-device group equivalent of
`sdifname`.

## Loading and recovery

The lifecycle planner uses `context.get_changed()` to compare previous and proposed
**effective** configuration. Changed chains, maps, sets and flowtables are destroyed
and rebuilt as complete objects. Unchanged objects are not flushed or redefined, so
they retain counters, last-used timestamps, cached flows and learned set members.
Global tracking and state-policy changes also invalidate the objects they affect.

The existing dependency registrar expands the affected objects through references
in both snapshots. Types remain distinct (`firewall-map-ipv4`, `firewall-map-ipv6`,
`firewall-address-group-ipv4`, and the corresponding types for other groups).
Changing a provider rebuilds every consumer, transitively: a set may affect a named
chain, a verdict map jumping to that chain, and further chains jumping through it.
Generated entrypoint chains are included when their target chains need rebuilding.
Changing a consumer does not rebuild its unchanged providers.

Selected chains are ensured and flushed to release their rules' references. Selected
maps, sets and flowtables are destroyed before the selected chains; verdict maps
must release their jump references before those target chains are destroyed.
Rebuilt named targets are declared before maps and rules. All these steps occur in
one kernel transaction; no partial ruleset becomes visible. Individual rules are
never patched in place. Unrelated tables and chains remain untouched; external
rules must not reference reserved managed objects.

The loader runs `nft --check --file` before applying the entire file with one
`nft --file` call. The create/destroy/rule operations constitute one kernel transaction:
packets see the old or new ruleset, with no intermediate missing chains. A rejected
batch leaves the previous rules intact. See the nftables
[atomic replacement documentation](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)
and [command reference](https://netfilter.org/projects/nftables/manpage.html).

The last successfully loaded artifact is `firewall.nft` in configd's state directory
(`/var/lib/nvyr/firewall.nft` in the packaged service). It is published only after a
successful load. The saved nVyR configuration remains the boot authority; this file
is an inspection artifact containing the last applied delta, not a standalone full
ruleset for replay. Replacing an object resets its counters and `last` state.

A load timeout or failure to publish the applied artifact has an uncertain outcome.
The loader raises a recovery error so the engine retains its journal and blocks
further commits until restart recovery restores the journaled configuration. Normal
commit-confirm rollback, history rollback, boot application and configd restart use
the same idempotent pipeline. The packaged service starts after nftables and restarts
alongside it. `save` is still required to retain a committed configuration across boot.
Recovery deliberately rebuilds all configured objects and inventories reserved
runtime namespaces to remove objects from an interrupted apply that never reached
persisted running configuration. This also resets runtime counters and learned
members. Normal commits use configuration snapshots and registered dependencies;
they do not need a runtime inventory.

## IPv6 DSCP range limitation

**Known nftables issue:** Packet tests with Debian nftables/libnftables 1.1.7-1 on
kernel 6.18.54.1-microsoft-standard-WSL2 found that native IPv6 DSCP interval sets,
such as `ip6 dscp { 8-16, 63 }`, load successfully but fail to match DSCP 10.
The same failure occurs with direct nft commands without nVyR. Individual DSCP
values and IPv4 ranges pass. nVyR preserves native expressions and includes a
failing opt-in regression, `test_real_ipv6_dscp_range_packet_matching`, to expose
this dependency issue. No range-expansion workaround is applied. IPv6 DSCP ranges
need an nftables fix and packet-level verification on the target image before use.

## Timeout-group replacement

Changing a group replaces its native objects and affected chains in the same
nftables transaction. Unrelated chains are preserved. An `inet` group generates
one native timeout object per IP family, selected by one family-neutral rule.

## Tests

Ordinary tests mock the live loader. Opt-in `tests/test_nftables_live.py` tests use a
fresh network namespace inside the privileged Debian test container. They check real
IPv4/IPv6 packet drops, counters, `last`, replacement/removal, rejection of invalid
loads and preservation of unrelated chains. A peer network namespace exercises raw
`notrack`, continuation, disabled rules and generated log expressions. Enable them with `NVYR_NETWORK_TEST=1`
only in that disposable container.
Named-chain coverage includes cross-family isolation, forward jumps, changing jump
dependencies, packet drops, removed/renamed targets, loop rejection, NAT preservation,
and recovery of unpublished chains. `test_named_chains.py` also checks CLI paths,
shared schema options, default handling and deleted-parent cleanup.
