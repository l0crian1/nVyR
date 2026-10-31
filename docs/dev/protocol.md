# How the CLI and Python API communicate with configd

nVyR's CLI and Python configuration API send requests to `configd`, the daemon
that owns configuration sessions and applies changes to the router. They connect
through a local Unix socket at `/run/nvyr/configd.sock`. This document describes
the messages on that connection and the records configd writes to recover after
a restart or failed commit. Both client and daemon run on the same router; the
socket carries local requests between them.

For example, when you type `compare | commands`, the CLI sends that command as
text. Configd evaluates it against your session, sends back the output, and marks
the request complete. The CLI displays the response; it does not maintain its own
copy of the router's configuration.

Use the [configuration session library](config-session.md) when writing automation.
It handles these messages for you. The details below are useful when working on
that library, the CLI, or configd itself. For operational-script authoring, see
[operational scripts](opmode.md).

## Connection ownership and permissions

Each socket connection owns zero or one configuration session. Opening a session
creates a private candidate for that connection; other clients cannot attach to it
by supplying its session ID. Requests on a connection are serialized: the client
finishes one exchange before sending the next, including background status polls.

Linux `SO_PEERCRED` supplies the connecting process's kernel-authenticated UID
and PID. Configd resolves the Linux account and checks its current nVyR role on
each request. Socket filesystem membership permits connecting; it does not grant
configuration or command privileges.

The terminal path from `/proc/PID/fd/0` and a validated SSH source address from
`SSH_CONNECTION` or `SSH_CLIENT` in `/proc/PID/environ` provide session labels.
These appear in lock errors and takeover prompts. They are informational only;
authorization uses the authenticated account.

For containerized CLI sessions, configd identifies the peer's session cgroup and
reads the launcher's root-owned record to recover the original SSH/console terminal
and source. A matching UID and launcher process identity are required. The client
cannot supply these records or use them to change its role.

Clients cannot submit another identity, import Python modules, or ask configd to
read or write arbitrary files. For operational commands, the installed command
schema determines the executable and arguments; the request cannot override the
execution identity or environment.

## A request and its replies

Messages are JSON objects. Every request carries protocol `version: 2`, an `id`
that identifies the exchange, and an `operation`. The following example assumes
an open configuration session:

```json
{"version":2,"id":7,"operation":"execute","text":"compare | commands"}
```

Configd can send text while processing the request. Each reply carries the same
ID, so the client can associate it with the request:

```json
{"id":7,"text":"set system host-name edge-router\n"}
```

A successful exchange ends with `done: true` and a structured `result` object.
For this example, a session at the configuration root and commit ID 42 receives:

```json
{"id":7,"done":true,"result":{"export":null,"paging":null,"edit":[],"commit_id":42}}
```

A failed request instead ends with an `error` object containing `code`, `message`
and optional details. An error is a terminal reply; the client does not wait for
an additional `done` frame. `Client.request()` raises the corresponding Python
error. Session expiration has its own `SessionExpiredError` type.

`on_text` receives captured output as it arrives. Without that callback, the client
collects output and includes it as `text` in the returned result. An optional
`on_terminal` callback handles live terminal output separately; without it, terminal
output uses the same callback or collection behavior as captured output.

### Framing and size limits

On the socket, each JSON message has a four-byte unsigned, network-byte-order
length followed by that many bytes of UTF-8 JSON. A payload may be at most 64 MiB.
CLI and configd must use the same protocol version.

Text output is split into chunks of at most 32,768 characters, safely below the
byte limit even for Unicode. Configuration snapshots and imports are single
messages, so their complete encoded JSON must fit within 64 MiB. The limit includes
JSON escaping and request fields, not just the original configuration text.
Oversized encoded messages report the attempted byte size and the limit.

## Operations

The daemon accepts these operations:

- `open` and `close`: create or discard the connection's configuration session.
- `execute`: run a CLI command in the connection's current mode and edit context.
- `complete`: obtain completion candidates and help for partially typed input.
- `get_config` and `load`: retrieve a configuration snapshot or import content.
- `commit`: apply pending changes and return a structured result for automation.
- `status`: obtain session state and retained notifications without a snapshot.
- `clear-firewall-group`: clear learned firewall-group members through a restricted
  runtime operation.
- `geoip-update` and `geoip-status`: update or inspect the managed GeoIP data.

The CLI generally uses `execute` for commands a user types. The Python API also
uses dedicated operations such as `get_config`, `load` and `commit` to avoid
parsing display text.

## Configuration sessions

### Opening, closing and expiration

`open` accepts an optional positive finite `timeout` in seconds, a total lifetime
from creation measured by a monotonic clock. The daemon default is 28800 seconds
(8 hours), configurable through `--session-timeout`. Activity does not extend it.
The Python [configuration session library](config-session.md) supplies 300 seconds
by default. Expiration removes the candidate and session lock; subsequent session
operations return `session_expired`. `status` instead reports `session_expired: true`
so the CLI can remain in configuration mode and allow an explicit exit. `close`
discards uncommitted work and closes even an expired session; it is idempotent.

### Confirmations and drafts

Confirmable operations first return `confirmation_required` and concrete owner/session
or commit-ID details. The interactive client asks the user and retries with those details
in `confirmation`. This protects against a changed owner or commit between warning and
retry. Exiting a candidate with pending changes requires explicit discard
confirmation. Opening with `draft: true` creates a draft session; configd enforces
its restrictions, including preventing commits, independently of the client.

## Configuration snapshots and imports

`get_config` requires an open configuration session and accepts `source: "running"`
(default) or `source: "candidate"`. It returns a `configuration` dict in the result,
without implicit defaults, display markers or edit-context scoping. The snapshot
is captured under the engine lock and follows normal role-based credential
visibility. It is subject to the 64 MiB frame limit and session expiration.

`load` sends content, `set_format` and `replace` flags. The daemon handles only content,
not client paths. Set imports return per-line errors. The current single-request import
limit is 64 MiB for the complete encoded message, including JSON escaping and
request fields. Transfers use a single message, with no chunked upload mechanism.

## Commits and rollback deadlines

`commit` is the library's structured commit endpoint. Optional `n` requests a
commit-confirm timeout in seconds (greater than zero, at most 86400). Supplying
`n` explicitly authorizes that rollback deadline; it does not bypass role, lock
or stale-candidate checks. The response contains `changed`, `commit_id`, `results`
and lifecycle `messages` without CLI formatting. When lifecycles run, it also
includes `elapsed` seconds and `deadline` (a UTC Unix timestamp, or null).

The CLI asks for confirmation of `confirm_minutes` before applying a commit-confirm
command. If the candidate is stale, it also requests confirmation of the current
commit ID. After application, confirming that the configuration should be kept
uses `execute` with `text: "confirm"`. In-flight commits finish safely after session
expiry. Closing or expiring a session never cancels its pending commit-confirm
rollback or permits another commit ahead of recovery.

The optional `comment` field records nonempty single-line text with the published
revision. It never enters the configuration tree. No-op and entirely failed
commits do not record a comment. Confirmation retains the original comment;
automatic rollback creates a separate revision without a user comment.

### Feedback and client disconnection

CLI commit and validation progress arrives immediately as ordinary text frames,
followed by a summary and the final `done` frame. The `commit` operation used by Python retains its structured response.
A disconnected or non-reading feedback client does not fail a configuration
transaction: a stalled feedback write closes the connection after five seconds
and the engine completes publication/recovery normally.

The CLI ignores Ctrl+C while a commit is running and prints `Commit in progress`.
Losing the client connection is not a request to cancel or roll back the commit.

## Status, notifications and locks

`status` accepts an `after` event cursor and returns retained notifications,
session edit/commit metadata and the current event cursor without configuration
snapshots. Successful automatic rollback emits an
event once and synchronizes its originating session ID. The client advances its
event cursor after displaying notifications and serializes status with other
requests on the same socket.

Configuration-mode `show config-status` computes its detailed candidate/saved
comparison only on request; the background `status` RPC remains lightweight.
`release-session-lock` requires a configuration role and current lock ownership,
and cannot release during an active operation or commit-confirm lease. It leaves
the candidate, edit context and session intact.

## Completion and help

`complete` receives the text before the cursor. Its result contains up to 256
candidate/description pairs, a common-prefix `extension`, a possible `replacement`,
the replacement's `start` offset, and `unique`, `total` and `display` indicators.
Uniqueness and common prefixes use all matches before display truncation. No
command history is sent.

Request flags distinguish explicit help (`explicit`), Space abbreviation expansion
(`space`) and Tab completion (`tab`). Tab also permits schema-defined empty-argument
lists. Dynamic suggestors participate in completion; `suggested` identifies values
supplied only by those suggestors. `hints` are separate, display-only descriptions
and never become inserted values. `display: true` tells the CLI to show candidates
instead of inserting a hint.

For anchored commands, `groups` associates candidates with their contexts. The CLI
shows outer contexts first and the current context last, nearest the prompt.
Within a context, hints precede schema choices and suggestions. `<Enter>` appears
first when the command can execute. This presentation order does not change
candidate insertion or prefix calculation.

## Captured output and paging

Display results include `paging`: null for automatic paging, true for `| more`,
and false for `| no-more`. Paging happens in the interactive CLI after it receives
the complete response. It buffers captured text in a private temporary file, then
opens the pager. RPC and Python callers still receive the full text.

Leaving the pager does not cancel the completed command or leave unread replies
on the socket. Streaming commands instead use the terminal exchange below and
reject output modifiers.

The `shell` event asks the CLI to run its interactive shell child while retaining
the socket and daemon session.

## Live terminal commands

A command with `stream: true` beside its YAML `command` uses a pseudo-terminal
(PTY), which carries live output, keyboard input and terminal-size changes.
Captured and streaming operational commands both execute with configd's privileges.
The schema's inherited `access` level determines the minimum nVyR role: read-only
by default, net-admin for image management and shutdown, and dev-admin
for unrestricted `shellcmd` execution.

Configd checks permission at dispatch and again immediately before terminal
process creation. It uses the authenticated peer's current role, not a role claimed
by the client or the root identity inherited by an operational script.

### Terminal exchange

During a streaming `execute` request, the server sends `{"id":7,"terminal":true}`.
The client acknowledges with `terminal: "start"`, `rows`, `columns` and `term`.
Configd rechecks authorization and starts the command in a new session with its own
controlling PTY. Output uses normal `text` frames, decoded incrementally as UTF-8.
Client controls carry the same request ID and `terminal: "input"` with base64 `data`
(at most 32 KiB decoded), `terminal: "resize"` with dimensions, or
`terminal: "interrupt"` for SIGINT. Actual terminal Ctrl-C also works through PTY
input. There is no command-launch control message.

When execution ends, configd stops remaining processes in its process group and
sends `terminal_end: true`. The client restores its terminal and acknowledges with
`terminal: "finish"`. Configd drains in-flight input before accepting the next RPC.
The final response includes `event: "command"` and `returncode`, with the normal
edit/commit metadata. Timeouts return an error after terminal cleanup. Disconnects
cancel the process group. `protocol.Client` implements the exchange and preserves the
connection/session; CLI and configd must both use protocol version 2. Streaming
commands reject output modifiers before starting a terminal exchange. Modifiers on
captured commands continue to use ordinary text frames.

## Managed firewall runtime operations

`clear-firewall-group` is the internal endpoint used by the firewall operational
script. Its `text` contains a complete `clear firewall group ...` command, parsed
against the same operational schema. It requires net-admin access even without
an open configuration session. Configd checks the running dynamic group and holds
its engine mutex through the nftables operation; active commits, rollback and
unhealthy recovery state reject cleanup. This endpoint cannot clear static groups,
execute arbitrary nftables commands, or modify the candidate/saved configuration.

`geoip-status` is available to operators; `geoip-update` requires net-admin.
These endpoints run the managed GeoIP status/update operations without requiring
an open configuration session. See [GeoIP address groups](../users/firewall-geoip.md) for
the updater's behavior.

## Persistent records and recovery

The socket protocol is transient; these files preserve configuration and recovery
state after the connection or daemon ends. Configd's default state directory is
`/var/lib/nvyr`, created with mode 0700. The saved configuration lives separately
under `/config` so it survives image upgrades.

### Files and safe writes

JSON records are written to a private temporary file and flushed to disk with
`fsync`. The file is then atomically replaced and its parent directory fsynced.
A process-level `flock` guards the state directory across initialization and recovery.
A separate listener lock prevents unlinking a live daemon's socket.

- `state.json`: current explicit tree, monotonically advancing ID and Linux boot ID.
- `/config/nvyr-saved-config`: explicit running tree from the last successful save.
  Reserved `_nvyr` file metadata identifies factory seeds (`factory: true`); explicit
  saves use `factory: false`. Store/load strip metadata before using the tree.
  `Store` keeps `boot.json` as its internal key; custom development state directories
  still use that filename unless `--saved` overrides it. System saves are root-owned
  0644 in a sticky `/config` directory, readable but not replaceable by ordinary users.
- `interface-names.json`: physical-port to `ethN` assignments, owned by the naming
  service rather than configd. Retain with host state across upgrades; configuration
  saves and rollbacks do not modify this file.
- `history/00000000000000000042.json`: resulting explicit tree, Unix timestamp,
  reason, user and optional comment (null when omitted).
- `transaction.json`: pre-state while a live commit outcome is uncertain.
- `confirmed.json`: pre-state, owner and deadline for an unconfirmed commit.
- `daemon.lock`: advisory process ownership; not a persistent user/session lock.
- `snapshot.lock`: image migration coordinates copies with durable record writes.

### Revision history

The history offset is an arithmetic distance in commit IDs, not a timestamp. Initial
empty state is ID 0. `set system configuration commit-revisions N` controls retention,
with an always-default of 20 and a minimum of 1. The count includes the current
revision. Configd prunes after durable publication, including startup and recovery,
using the published setting or its schema default when absent. Deleting the setting
restores 20; increasing it cannot restore already-pruned history. Revision IDs are
never renumbered. Pruning does not affect saved configuration or recovery records.
Comparisons to pruned IDs return a clear error. Recovery pre-states are embedded in
their own records and do not depend on retained history. Candidate journals are transient
and disappear on disconnect/restart; draft proposals can be exported for durable review.

### Recovery after an interrupted commit

History and state form a multi-file publication protected by the transaction record.
If the process crashes between writes, startup reconciles to the pre-state rather than
assuming an uncertain live apply completed. The recovery itself is idempotent and its
record remains until durable completion. Confirmed rollback failure keeps its record
and its lock; the timer retries. Corrupt persistent JSON fails startup; it is never
silently replaced with an empty router configuration.

## Implementation references

- [protocol.py](../../src/nvyr/protocol.py): framing, message limits and the shared client.
- [daemon.py](../../src/nvyr/daemon.py): peer authentication and operation dispatch.
- [controller.py](../../src/nvyr/controller.py): CLI execution and completion.
- [terminal.py](../../src/nvyr/helpers/terminal.py): live terminal exchange.
- [storage.py](../../src/nvyr/storage.py): durable records and publication.
