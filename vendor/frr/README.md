# FRR reload fixes

`reload-ordering.patch`, `keychain-reload.patch`, `ospf-reload.patch`, and
`rip-reload.patch` modify FRRouting's `tools/frr-reload.py` from tag
`frr-10.7.1`, licensed GPL-2.0-or-later. `COPYING` contains GPL version 2.

Upstream copyright: Copyright (C) 2014 Cumulus Networks, Inc.
nVyR changes: Copyright (c) 2026 L0crian and nVyR contributors.
The patch remains GPL-2.0-or-later and is excluded from the repository's MIT license.

Source: https://github.com/FRRouting/frr/blob/frr-10.7.1/tools/frr-reload.py

Original source SHA-256:
`f8263f841b13382ffd75e0478d2fc75d620df20d89ff217db8b1a4eb9efdb70c`

`reload-ordering.patch` changes BGP list deletion ordering in
`ignore_delete_re_add_lines()`. The upstream optimization moves deletions into
the bulk additions, after replacement commands. This breaks AS-path regex
replacement at an existing sequence and community-list standard/expanded type
changes. Our change keeps bulk execution but places BGP list removals first.
It covers AS-path, community, large-community and extended-community lists.

`build_tools/frr_packages.py` applies the patch while building FRR's Debian
packages with the `pkg.frr.lua` profile. The resulting `frr-pythontools` package
owns `/usr/lib/frr/frr-reload.py`, used by the shared FRR manager; nVyR no longer
ships a separate executable. The source archive is pinned in
`images/frr-sources.lock` and the patch participates in the package cache key.
Reevaluate and remove this patch when an upstream version fixes the ordering.
Regression coverage is in
`tests/test_frr_reload_ordering.py`, `tests/test_policy_live.py`, and the IPv4
and IPv6 AS-path exchange tests in `smoketests/test_bgp_policy.py`.

`keychain-reload.patch` fixes lifetime round-trip defects. The running
configuration pads single-digit days while the file loader collapses whitespace;
the patch normalizes lifetime whitespace in both representations. Removing or
replacing a lifetime emits `no accept-lifetime` or `no send-lifetime`, without
the positive command's time operands, as required by FRR's CLI grammar.
This also prevents unrelated protocol reloads from attempting to change existing
lifetimes. It also corrects `lib/keychain_cli.c`'s removal handlers to address
`./lifetime/accept-lifetime` and `./lifetime/send-lifetime` below the current key.
The original relative paths referred to nonexistent nodes and failed even when
the CLI command was syntactically correct.

The native source is also GPL-2.0-or-later, copyright (C) 2000 Kunihiro Ishiguro:
https://github.com/FRRouting/frr/blob/frr-10.7.1/lib/keychain_cli.c

Regression coverage is in `tests/test_frr_reload_ordering.py` and
`tests/test_policy_live.py`. Remove this patch once these defects are fixed upstream.

`ospf-reload.patch` uses the native reset syntax for aggregation timers,
adjacency logging, and OSPFv3 graceful restart. It also removes static OSPFv3
neighbors after their dependent options: resetting a cost or poll interval after
deleting the neighbor otherwise recreates it. These changes affect deletion and
replacement, not the positive configuration grammar. Live coverage is in
`smoketests/test_ospf.py`; reevaluate this patch when upgrading FRR.

The same patch limits the opaque-extension configuration writer to the default
VRF, matching the native commands' scope. Otherwise the global Router Information
setting is written into every VRF process and cannot be replayed there.
`ospfd/ospf_opaque.c` is GPL-2.0-or-later, copyright (C) 2001 KDD R&D Laboratories,
Inc. Source: https://github.com/FRRouting/frr/blob/frr-10.7.1/ospfd/ospf_opaque.c

Area stub/NSSA state is also removed after dependent default-cost settings.

`rip-reload.patch` restores a removed per-interface passive exception to the
target RIP process's passive default. Simply reversing a negative exception
would make that interface passive even when the same reload removes
`passive-interface default`. Resets run after process-default changes, and
explicit replacement exceptions retain their normal handling. Native coverage
in `tests/test_rip_native.py` exercises both transitions and verifies configuration
readback. Reevaluate this patch when upgrading FRR.
