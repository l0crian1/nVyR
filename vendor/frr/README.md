# FRR reload ordering fix

`reload-ordering.patch` modifies FRRouting's `tools/frr-reload.py` from tag
`frr-10.7.1`, licensed GPL-2.0-or-later. `COPYING` contains GPL version 2.

Upstream copyright: Copyright (C) 2014 Cumulus Networks, Inc.
nVyR changes: Copyright (c) 2026 L0crian and nVyR contributors.
The patch remains GPL-2.0-or-later and is excluded from the repository's MIT license.

Source: https://github.com/FRRouting/frr/blob/frr-10.7.1/tools/frr-reload.py

Original source SHA-256:
`f8263f841b13382ffd75e0478d2fc75d620df20d89ff217db8b1a4eb9efdb70c`

nVyR changes only BGP list deletion ordering in
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
