# Architecture

## Ownership of state

`configd` owns one explicit running tree and a mutation journal for each connected
configuration session. A session stores identity, mode, edit path, observed commit ID
and mutations. It never stores a baseline configuration snapshot. The CLI stores mode
and edit-path display metadata; all configuration operations and prediction queries go
over a Unix socket.

Trees are immutable by convention after publication. `put`, `remove`, `apply` and
`overlay` return copy-on-write roots and share untouched children. `ReadOnlyTree` gives
modules a lazy read-only API over that shared tree. Modules are trusted code, so this is
an accidental-mutation guard rather than a Python sandbox.

Full candidate overlays replay the journal as one private batch. Each shared
dictionary is copied on its first write and reused for later edits in that batch,
avoiding a full copy of a wide rule collection for every field assignment.
Mutation order is unchanged, including ancestor deletion and replacement. Inserted
subtrees remain borrowed until modified, so replay cannot alter running state or
values retained in the journal. Write ownership ends when the overlay returns;
subsequent overlays must copy again before modifying a published branch.

Mutations are `set`, `delete`, `ensure`, `add` and `subtract`, each with an absolute tuple
path and, for owned settings, a script owner. Ensuring an organizational container
above the ownership roots changes stored structure without invoking a module.
Scalar writes replace; multi-value writes add unique strings;
subtract removes one multi value; ensure records an empty container without replacing
existing children. Valueless leaves are `true`. Deleting a child preserves its parent
containers, including empty tag instances, tag collections, and plain nodes. Delete
the parent explicitly to remove it. An ancestor deletion spanning several owners is
split into owner deletions with cleanup bounded by the explicitly requested path;
a failed owner's remaining subtree prevents that ancestor from disappearing.
Empty containers survive native/set imports, exports, save, and restart. Configuration
scripts decide whether an empty object is valid during verify; static routes require
at least one next hop. Earlier writes are retained before deletion intents because
they may establish parent containers even before the first commit.
Multi leaves are ordered by insertion for display, but membership determines CLI diffs.

Setting an already configured value reports `Configuration already exists:` followed
by the full individual `set` command, with quoted values and sensitive values redacted.
The check projects the requested path through running configuration and pending
mutations; implicit defaults do not count as explicit configuration. Duplicate
operations are skipped rather than recorded as intents. In an anchored command,
other new settings are still staged, and each duplicate gets its own notice. An
invalid command is still rejected in full before any settings are staged. Pastes
continue after duplicate notices. Replacement loads check against the replacement
tree, so values shared with running configuration are retained in the file's result.
Skipped duplicates do not pin a value against another session's subsequent commit.
Repeated changed scalar writes at the same path are compacted. The journal keeps
intents in order and indexes them in a path tree. Duplicate checks select only
ancestor, exact-path and descendant intents; scalar replacement removes earlier
intents directly at that path. Neither operation scans unrelated pending rules.
The index stores mutations, not a second candidate configuration, and is cleared
or rebuilt with the journal on discard, load, partial commit and session cleanup.
All reads evaluate against the current running root. Completion normally projects
only the requested branch through relevant mutations. Projecting a deleted owner's
ancestors uses the full overlay to assess bounded container cleanup against sibling
state; value checks beneath those deletions stay targeted. Pending removals suppress running
values; external suggestors may still independently discover an existing OS object.

## Parsing and prediction

The same lexer retains quoted token values, source spans and pipeline separators for
interactive commands, multiline submissions and set imports. Unquoted spaces separate
values; pipes inside quotes are ordinary characters. JSON nodes distinguish keyword
nodes, named tag containers and leaves. Resolution uses exact keyword matches first,
then unique prefixes; ambiguity is an error. Prediction always keeps *all* prefix
matches, including longer words when the current prefix is also an exact keyword.

The control and operational schemas share resolution. `run` uses the real operational
schema. `set`, `delete` and `edit` resolve against the configuration schema with the
session's edit path prepended. Edit accepts plain nodes and named tag instances;
`up` skips bare tag containers, preserving valid instance ancestors. Scoped show paths
use the same resolver and edit-relative semantics. Rename supports instances within the same
schema tag node, including relative paths, and records daemon-side delete/set intents.

`copy <source path> to <destination path>` uses the same tag-instance resolution,
but leaves the source in place. For example, after
`edit firewall ipv4 forward filter`, use `copy rule 10 to rule 20`. At the root,
use `copy firewall ipv4 forward filter rule 10 to firewall ipv4 forward filter rule 20`.
Both paths must identify instances of the same schema tag node, the source must
exist in the candidate, and the destination must not already exist. Empty instances
can be copied. The copy contains explicit settings, including pending edits and
nested values; defaults remain implicit. References retain their original values.
The daemon stages the operation atomically with its normal permissions and
dependency checks. Later changes to either instance are independent, and nothing
is applied to the host until commit; discard removes the staged copy.

For `set`, explicitly anchored nodes and tag instances establish return points.
`SetCursor` wraps the ordinary schema cursor only while parsing/predicting: completed
leaves return to that anchor before the next token. `Schema.set_paths` expands the
whole line into validated absolute cursors before any mutation is staged. Those become
the same ordered set/add/ensure intents as individual commands; no downstream tree,
commit, script or persistence format tracks anchored syntax. The edit root limits
anchor discovery. Nested anchored nodes and tag instances create local option groups
while retaining outer return points. Unanchored nested tags return to the outer anchor.
See the authoring guide for precedence and exact operation boundaries.

The CLI's autosuggestion, Space expansion, Tab and possible-completion display all call
one daemon endpoint. All completion modes invoke registered suggestors. Informational leaf and tag hints travel
separately and are only rendered in Possible completions. Suggestors do not restrict accepted values. Configured local values
and schema choices are available to ordinary Tab and inline suggestions. Quote-sensitive
completion preserves a single token. Separate persistent histories support Up/Down in
each mode. The history adapter records submitted commands individually, including
pasted commands, but history is never an input to the prediction endpoint. Central
validator and suggestor registries are loaded once at import. Compare and rollback
share a completion suggestor reading retained snapshots and their real timestamps.

Pipelines resolve through a separate schema and handler registry. `Output` can carry
configuration/diff references as well as its text representation. `commands` consumes
that structured data; text filters discard the type information. `export` must be last.
Every modifier's syntax is checked before command execution. File writing happens in
the CLI user process via a temporary file and atomic replacement.

Candidate rendering derives changed branches from running and the overlaid proposal;
it stores no second candidate model. Minus/plus lines preserve removed/replaced values.
The shared marked-JSON renderer walks matching object keys recursively. Added/deleted
subtrees stay contiguous, scalar/list replacements show old then new values, and each
side retains its own trailing commas. Text resemblance never aligns unrelated paths.
Scoped output retains root references and a resolved scope, so command serialization
cannot broaden a requested deletion to a parent outside that scope.
`show`, its running/candidate selectors, and `compare` honor the current `edit`
context. An explicit show path selects a subtree relative to that context.
`| commands` emits paths relative to the selected subtree; at the root it continues
to emit full paths. Candidate views retain their existing pending-change semantics.
Plain `show | commands` includes unchanged settings alongside pending additions,
replacements, and deletions, matching the scope of its marked JSON display.
`show candidate-configuration | commands` and `compare | commands` remain changes-only.
For example, `show running-configuration interfaces | commands` emits
`set dummy dum0 address 150.0.0.1/32`, as does the same display after `edit interfaces`.
Nested edits narrow the context further, so editing that dummy interface emits
`set address 150.0.0.1/32`. A selected leaf, or an empty/removed selected object,
retains its name relative to its nearest editable parent when the command must
address the selected item itself; this avoids bare `set`/`delete` commands.

`show running-configuration all` displays the effective running configuration,
including applicable `direct` and `always` defaults. In configuration mode,
`show all` displays the complete effective candidate, including unchanged settings,
without change markers. `show candidate-configuration all` remains restricted to
top-level sections with pending changes and includes their complete effective
settings and applicable defaults. Entirely deleted sections retain deletion
markers and produce `delete` commands with `| commands`. With no pending changes,
the candidate view is empty. Normal displays retain their existing behavior.
Place `all` before any relative configuration path,
for example `show running-configuration all interfaces`. Edit contexts still apply;
operational mode and configuration-mode `run` start at the root.

These views use the same default expansion as configuration application. They do
not change candidate mutations, running state, saved configuration, or history,
and they preserve credential visibility and `strip-private` masking. Output
modifiers operate on the effective view: `| commands` includes defaults as `set`
commands. Replaying those commands makes those values explicit. This is a view
of configuration-derived settings, not live kernel or service state.

Both schemas resolve `shell` to one client-side event. After prompt_toolkit returns
the terminal, `process.interactive_shell` starts a child with inherited terminal and
environment, waits, and restores parent signal handling. The daemon connection stays
open; no configuration session is recreated. Status is refreshed on shell return.
Captured operational output instead uses `process.cmd` with argv, timeout and checked
exit status, without a shell interpreter.

## Defaults

Only explicit configuration enters running, candidates, history and saved boot files.
The commit engine builds the intended full root once and applies defaults to an
effective root shared by all affected lifecycle calls.
Feature scripts in `nvyr.config_scripts` can read the entire effective object, including
other owners' proposed values. The firewall script passes this view directly to its
template; ownership limits publication and dirty tracking, not configuration reads.

`direct` checks whether the leaf's direct parent exists in the **explicit** tree.
`always` activates inside a top-level branch that exists explicitly, and may synthesize
plain structural ancestors below that branch. Defaults never synthesize tags; traversal
under a tag requires an explicit instance. Earlier defaults cannot activate later
`direct` defaults. Explicit values always win. A defaulted valueless leaf becomes true.

## Commit units and concurrency

Script declarations can appear at multiple locations, including beneath tag nodes.
Ownership is inherited until another script declaration takes over. Configd compares
each owner's own sections, excluding nested sections belonging to other scripts, and
runs each changed owner once. A static-route edit inside an existing VRF therefore
selects `static`, without selecting `vrf`. An ancestor deletion or whole-object copy
selects every owner whose section actually changes. No candidate or script import
name is accepted as an executable path.

YAML `script.register` fields accumulate into an owner-keyed dictionary. Literals and
enclosing tag values produce deduplicated lists, such as
`{'static': {'vrf': ['default', 'BLUE']}}`. Commit contexts expose current and previous
registrations, including unchanged instances. These are derived from configuration;
they are not editable values or a second persisted source of truth. Per-command
candidate mutations retain their targeted journal lookups.

A daemon mutex protects state transitions. One commit/recovery may run at a time.
Lifecycle work runs on a worker thread, outside the state mutex, allowing the event loop
to service other clients and promptly reject lock transfers while busy. Candidate
mutation is also rejected during an active apply; readers can inspect the last published
root. This deliberately simple first concurrency policy avoids writes racing publication.

Commit verifies lock ownership and the requesting session's observed commit ID. Stale
sessions need confirmation tied to the **current** commit ID; if it changes again, they
must confirm again. Live lock takeover similarly confirms the actual owner session ID.
Drafts cannot own a lock. Sessions belong to their authenticated socket connection/VTY
and also have a fixed total lifetime (eight hours by default for the CLI). Activity
does not extend it. Expiration or EOF clears the candidate and releases an ordinary
lock. This does not depend on PID reuse or a stale on-disk lock record.

Changed units and YAML-declared reapply consumers run through `get_config`, `verify`,
`generate`, `apply`. Required providers run first; otherwise `(priority, name)`
determines order. Failure retains that owner's pending intent while independent units can
continue. Newly nested configuration is blocked if creation of its enclosing object
failed. If child removal fails after a parent was removed, configd restores the parent
owner before publishing; failed restoration retains the transaction journal and marks
recovery required. Watched provider/consumer changes are also restored together when
one fails, preventing publication of new provider state with stale consumers.
If that restoration removes a newly created parent, its successful child owners are
restored too. For example, rolling back a new VRF also removes its newly applied BGP
and static sections, rather than publishing a VRF without a routing table. Nested
ownership and watch relationships are followed until the restoration set is complete.
Normal commits invoke each owner once; compensation is a separate recovery invocation. Only successful `apply`
authorizes publication. Cross-owner mutations are split when necessary to retain only
unpublished changes; ordinary failed intents keep their original rebase semantics. One invocation publishes at most one new commit ID and one resulting
historical snapshot. The committing session receives that ID even on partial success.
No-op commits produce no ID or snapshot. Expected exceptions are clean user errors;
unexpected exceptions are logged with a daemon traceback and a controlled client error.

`commit comment "Description"` and `commit-confirm 1 comment "Description"`
attach optional comments to the resulting history record, outside the configuration
tree. The Python API accepts the same metadata through `commit(comment=...)`.
`show commit-history` displays retained snapshots newest first, their permanent
commit IDs, relative revision offsets, UTC timestamps, authors and comments.
Offsets follow compare/rollback arithmetic even when history has gaps. Confirmation
does not rewrite the original revision metadata; no-op commits do not overwrite it.

`commit check` selects the same changed owners and order as commit, but stops each
lifecycle after `get_config` and `verify`, using `context.check_only=True`.
It does not generate or apply configuration, change candidates/running state,
acknowledge stale commit IDs, save files, create history or acquire the commit lock.
Normal and draft configuration sessions can check their candidates. Configuration
permissions and login-account protections still apply. The engine excludes other
mutations/commits during verification and rejects checks during a pending
commit-confirm, so checking cannot delay its rollback timer. Expected failures are
reported per owner; unexpected failures are logged and leave the engine usable.
The SSH listen-address and static next-hop host-address checks are explicitly
reported as deferred until commit, since pending interface changes may alter
those addresses. Normal commits and recovery retain full verification.

An unrecoverable live compensation failure is different: `RecoveryError` aborts the
commit, retains the pre-commit transaction record and blocks further writes until
restart recovery. Ethernet uses this path if restoring its previous intent also fails.

All units inspect the same proposed effective tree. Priority is **not** a dependency
solver. A real module must verify its external prerequisites and own the consequences of
its live apply. The engine's atomic unit is publication of explicit configuration; it
cannot undo arbitrary kernel/process side effects if a module partially mutates them
and then raises. Modules must use atomic backends (such as an nftables transaction) or
their own compensation, with idempotent reconciliation for crash recovery.

Managed interfaces use the dedicated nVyR Netlink daemon for direct kernel
operations, monitoring and reconciliation, with udhcpc as a DHCPv4 protocol client.
The feature script validates device existence, generates a type-neutral interface plan
and applies it through `helpers/interfaces.py`. See [interface configuration](interfaces.md)
for driver extension points, ownership, actuation journals and compensation semantics.

## Durability and confirmed commits

Before live apply, a durable transaction record stores the pre-commit explicit state.
After successful units finish, history and current state are durably written before the
journal is cleared. A crash in any uncertain interval leaves the journal in place.
Startup restores the pre-commit state through all registered lifecycles before accepting
clients. If reconciliation fails, startup fails rather than serving an unverified router.
Publication errors likewise block further writes until restart recovery.

Confirmed commits persist their pre-state and owner before apply; the deadline starts
when publication finishes. The lock remains pinned after the owning connection closes.
The CLI requests confirmation tied to the timeout before starting live application.
No new commit, save or lock takeover is permitted until confirm or automatic rollback.
Any authorized administrator in a normal configuration session can confirm the
pending running revision, including after reconnecting. Confirmation requires no
commit lock, leaves candidate edits untouched, and records the confirming user and
commit ID in configd's log. It releases a disconnected owner's stale lock without
taking the lock for the confirmer; a live owner's lock remains unchanged.
Confirmation and expiry are serialized: an expired deadline or active rollback
cannot be cancelled by a late confirmation. Reconnecting never extends the timer.

At expiry the engine reapplies affected units to the pre-state. Failure retains the
durable rollback record and pinned lock and is retried. On daemon restart, an outstanding
confirmation is conservatively rolled back immediately; the timer is never silently
extended. Manual rollback instead stages only differences in the caller's candidate.

Successful timer rollback updates the originating live session's observed commit ID
and emits a retained status event once. A background status request lets an idle CLI
display that event outside the prompt and redraw without disturbing typed input.
Other sessions retain their IDs and still require stale-configuration confirmation.
Failed recovery neither emits a success event nor updates the session ID prematurely.

## Scheduled commits

`commit delay <minutes>` and `commit-confirm <minutes> delay <minutes>` freeze a
copy of the requesting session's mutation journal after checking authorization
and the current running revision. Verification runs before the schedule is
accepted; its delay begins afterward. The commit lock remains reserved even
when the originating session disconnects or expires. Other sessions can prepare
candidates but cannot commit, save, take the lock or run competing checks.

Configd's timer claims each due schedule once, restores the original caller's
authorization context, rechecks verification, and invokes the ordinary commit
pipeline. Configuration revisions, partial-failure handling and rollback journals
remain shared with immediate commits. The confirmation deadline starts at
publication, not scheduling. A live originating candidate keeps later edits and
unapplied changes; already-applied intent is removed.

`cancel` requires configuration permission and a normal session, not lock
ownership. It cannot interrupt a claimed job. Completion/failure is logged and
emitted as a retained status event. Only scheduling metadata is written to
`scheduled.json`; the frozen candidate remains in memory. Restart cancels the
schedule and logs its originator. An execution interrupted by restart follows
the existing transaction and commit-confirm recovery rules.

Daemon restarts reconcile the durable running state. A changed Linux boot ID selects
the separately saved boot configuration. Thus unsaved commits survive a daemon restart
but do not become boot configuration. A machine reboot also reconciles interrupted and
unconfirmed work before selecting saved state. Recovery reconciles the required
states before accepting client requests.

## Scaling boundaries

Candidates consume journal-sized memory. Copy-on-write views share unchanged subtrees,
and the CLI receives only requested rendered output or completion metadata. History
uses full JSON snapshots because this makes recovery and inspection straightforward.
Retention defaults to 20 snapshots, including the current revision. Output frames
are bounded; rendering still builds complete requested text daemon-side. Completion must inspect matching configured
values and journals; extremely large tag containers remain a benchmark target. A
persistent map, mutation trie, paged rendering and import streaming are future options
to evaluate against measured workloads.

`python -m tests.commit_benchmark` measures candidate construction and complete
engine commit overhead with real journal staging and durable temporary storage.
Feature lifecycle implementations are replaced by test doubles, so the results
exclude firewall verification, rendering and nftables execution. Use `--sequential`
to compare against individual copy-on-write replay, or `--profile` for a separate
profiled run. The benchmark does not change the host's configuration.
