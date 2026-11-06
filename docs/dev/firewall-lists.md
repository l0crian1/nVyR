# External firewall membership

For commands and behavior, see the [user guide](../users/firewall-lists.md).

`helpers/firewall_lists.py` implements retrieval, per-entry validation,
deduplication, cache snapshots and direct element updates. It uses the existing
nftables manager, task scheduler and rsyslog routing; there is no updater daemon.

## Configuration lifecycle

- `firewall.get_config()` gathers the existing firewall tree.
- `verify()` checks attachment completeness, membership exclusivity and column
  coverage. Existing checks enforce family/hook restrictions and reject including
  imported groups in other groups.
- `generate()` reads compatible cache data or retrieves new sources, validates
  rows and formats replacement statements for objects in the lifecycle rebuild
  set. It also renders the attachment schedules. It returns rules, prepared cache
  and units, without applying native membership.
- `apply()` installs the combined firewall transaction, reconciles schedules and
  publishes the prepared cache. Publication failures after a successful native
  transaction require recovery rather than reporting a successful commit.

CSV column schemas are derived from existing entry fields by
`build_tools/schema_builder.py`. Scalar values pass through those same installed
validators; individual rows also use the existing relational group checks.
Invalid rows are warnings, not invalid configuration. URL and column configuration
errors remain ordinary CLI/verification failures.

Keys use the firewall's canonical interval representation. Dictionaries provide
deduplication; each surviving key gathers attachment names in a set. Conflicting
map results remove the complete key and mark it ambiguous so later occurrences
cannot reintroduce it. Element comments are sorted origin names, bounded by the
native 128-byte limit. Native interval auto-merge is retained. nftables 1.1.7 can
merge adjacent ranges with different comments and keep just one comment; tests
record that limitation rather than requiring provenance-preserving merging.
Single-field maps reject overlapping intervals natively. A sorted interval sweep
excludes every member of an overlap cluster and warns, without choosing a result
or doing quadratic pairwise comparisons. Concatenated maps retain native support
for distinct intersecting keys.

## Updates and transaction safety

Manual operational commands and scheduled jobs call `firewall-list-update` on
configd. The request requires net-admin access. A refresh snapshots the effective
running configuration, retrieves outside the engine mutex, and rechecks the
configuration and engine state before applying. Concurrent commits/recovery or
refreshes cause a busy response. Native replacement uses flush/add in one atomic
nftables transaction; consuming rules retain their handles and counters.
Attachments with identical schedules share one timer and retrieval batch, even
across groups. Different schedules coinciding wait outside the engine mutex.

`/config/firewall/lists/cache.json` stores parsed records, file hashes, source and
column signatures, counts, errors and source text. The text allows cached verdict
rows to be rechecked when their target chains or calling hooks change. Schedule
changes alone do not require reimport. No network resolution is performed for
membership values. curl has a two-second connection timeout, five-second total
timeout and six-second subprocess deadline; ten workers bound concurrent fetches.

`rollback.json` pins cache snapshots against configd's transaction and confirmed
commit journals. Recovery chooses the pinned before-image without downloading.
The confirmation deadline is excluded from pin identity because configd updates
it after a successful apply. Runtime refreshes during the confirmation window do
not overwrite its before-image. Ordinary refreshes create no configuration
revision. Removed journal pins are cleaned on the next list operation.

Imported verdict maps conservatively depend on their family's named chains, so
chain changes rebuild affected maps and recheck cached jump results. Direct
refreshes do not run the full firewall configuration script. Imported groups
cannot be included in other groups, avoiding an additional update dependency
graph. Dynamic entries are intentionally not preserved on changed-file updates.
Imported entries in dynamic sets use the same configured timeout as learned
entries. Hash-identical refreshes do not repopulate expired imports.

## Verification

`tests/test_firewall_lists.py` covers parsing, ambiguity, canonical deduplication,
cache reuse, bounded concurrent retrieval, column anchoring and rollback pins.
`tests/test_firewall_lists_live.py` uses isolated network namespaces to exercise
native membership and packet verdicts, unchanged-file updates and comment merging.
The smoketest checks rendered/installed membership and scheduled units. Acceptance
loads persistent list/CSV fixtures and checks them before and after reboot.
Functional checks share the routed-network scenario and change imported policy
without creating another topology.
