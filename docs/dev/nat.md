# IPv4 NAT and NAT66: implementation and maintenance

For configuration and command usage, see the [user guide](../users/nat.md).

## Shared table and atomic application

NAT uses the existing `inet nvyr_filter` table. Its entry points are:

- `nat_prerouting`: DNAT at priority `dstnat` (-100).
- `nat_postrouting`: SNAT at priority `srcnat` (100).

Each entry point dispatches by `meta nfproto` to the numbered rules for that direction:
`ipv4_nat_<hook>` for `nat`, `ipv6_nat_<hook>` for `nat66`. Only configured
directions participate, so even an unqualified masquerade or port-only translation
cannot cross families. Removing the last family removes the shared entry point.

The Jinja template consumes the shared configuration view directly. `nft_nat_rule()`
uses the same `NFT_KEYMAP` match/statement renderer, deterministic value ordering and
comment builder as firewall rules. `NFT_NAT_KEYMAP` uses the same `NftKey` metadata
to render translation targets and flags in canonical order; action expressions and
log labels come from `NFT_NAT_ACTIONS`. Only NAT's address/port separator syntax
requires specialized handling. Default port mapping emits no flag, and masquerade
selects an action rather than rendering a literal address.
Rendering trusts schema validation and `verify()`; it does not revalidate values,
allowed paths, flags or cross-field requirements.
Shared schema fragments live under `schemas/includes/nftables/`; NAT-specific
translation definitions live under `schemas/includes/nat/`.

Firewall, maps, and source/destination NAT share the `firewall` commit owner and
one nftables transaction. The lifecycle planner replaces whole changed chains and
expands changes through registered map/set dependencies. It releases references
before replacing objects, and preserves unchanged chains and groups. Unrelated
chains/tables are preserved. External rules must not reference reserved nVyR objects.
The successfully loaded file is `/var/lib/nvyr/firewall.nft`.

A failure leaves both firewall and NAT changes pending. Confirmed rollback and
restart recovery apply both sections together. Existing conntrack mappings survive
rule updates/removal until they expire; new rules govern new connections. nVyR
does not flush all live connections on each commit.

## Validation

`test_nat.py` covers schema validation, rendering, shared matches, completion,
anchors, verification errors and the shared firewall artifact. Opt-in
`test_nat_live.py` uses disposable network namespaces to exercise SNAT, DNAT,
masquerade, address/port pools, port-only translations, exclusions, disabled rules,
IPv6 bypass, dual-stack translation and reply traffic, firewall coexistence, rejected transactions and lifecycle recovery.


NAT rules also accept `match-group <name>` without a map. The group supplies
matching criteria and the rule supplies `translation` or `exclude`. Matches from
the rule, map, and match-group must not overlap. An interface or protocol supplied
by a match-group satisfies the same requirements as an explicit rule match.

```text
set firewall group match-group ipv4 CLIENTS match source-address outbound-interface

set firewall group match-group ipv4 CLIENTS entry OFFICE source-address 192.0.2.0/24 outbound-interface eth0

set nat source rule 10 match-group CLIENTS translation address masquerade
```

## NAT lifecycle ownership

`nat.py` verifies IPv4 and IPv6 source and destination NAT as part of the shared firewall
commit owner. Filtering, NAT and their groups apply together at firewall priority
15, after interface scripts at priority 10. Both `nat` and `nat66` declare this same script owner.

## Structured operational output

Python operational entry points expose
`--raw` JSON for callers; JSON is not a CLI keyword.
