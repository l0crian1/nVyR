# Python configuration sessions

Local Python scripts can use the installed `nvyr.config_session` library to open
the same candidate configuration session as the CLI. All validation, permissions,
locking, application and recovery remain in configd.

For interactive commands, see [using the CLI](../users/cli.md). This guide describes the
local Python API and its shared session behavior.

`ConfigurationSession` connects directly to configd's Unix socket from the calling
process; it does not launch a CLI session container. Restricted interactive logins
run in containers, but both clients use the same daemon-side authorization,
session locking, and commit pipeline.

## Open a session

```python
from nvyr.config_session import ConfigurationSession

with ConfigurationSession() as config:
    config.set('set interfaces dummy dum0 description "Automation interface"')

    result = config.commit(n=30)  # Commit-confirm deadline in seconds.

    # Check connectivity or other health conditions here before confirming.
    config.confirm()
    config.save()

with ConfigurationSession() as config:
    config.delete('delete interfaces dummy dum0')

    config.commit()
    config.save()
```

`set()` and `delete()` accept full commands, including their verb, quoted values
and the existing schema's abbreviation behavior. Anchored `set` commands work
normally. Pipes and other command verbs are rejected by these methods. Duplicate
settings produce the existing notices and do not prevent new settings in an
anchored command from being staged.

## Methods

- `commit()` applies the candidate without a confirmation timer. `commit(n=30)`
  requests a 30-second rollback deadline. This API uses **seconds**; the existing
  interactive CLI's commit-confirm syntax continues to use minutes.
- `commit(comment='Added WAN firewall rules')` records an optional revision
  comment. It also works with `n`, for example `commit(n=30, comment='Test routing')`.
  Comments are nonempty single-line text and are stored outside the configuration.
- `confirm()` confirms the pending running revision from any authorized normal
  configuration session, including a new connection. It does not require or
  acquire the commit lock and does not apply candidate edits.
- `discard()` removes uncommitted changes from the candidate.
- `request_lock(force=False)` acquires an available commit lock or succeeds if
  this session already holds it. If another session holds it, the normal
  confirmation-required error identifies that owner. Use `force=True` to permit
  taking the lock from that specific owner. A change of owner during confirmation
  raises an error; the library does not repeatedly attempt takeover.
- `get_config(source='running')` returns the complete running configuration as a
  dict. Use `source='candidate'` for running configuration plus this session's
  pending changes. Both return independent snapshots without display markers or
  implicit defaults, regardless of the session's edit context.
- `load(configuration, replace=True)` accepts a configuration dict and stages it
  as the complete replacement candidate, superseding existing pending changes.
  Use `replace=False` to merge into the candidate instead. Schema validation,
  password hashing and role checks follow the normal configd load path. Invalid
  configuration leaves the candidate unchanged. Loading does not apply or save;
  call `commit()` to apply it and `save()` if persistence is desired.
- `save()` saves the running configuration, following the normal lock and
  pending-confirmation restrictions.
- `exit()` closes the session and discards uncommitted changes. Repeated calls
  are harmless. A `with` block calls it automatically, including on exceptions.
  It never commits, confirms or saves automatically. Closing an unconfirmed
  session leaves its rollback timer in force.

### Results and errors

Except for `exit()` and `get_config()`, methods return configd result dictionaries.
`load()` returns `{'errors': []}` on success; invalid dict loads raise an exception.
`set()`/`delete()` include notices in
`text`. `commit()` includes `changed`, `commit_id`, per-owner `results` and lifecycle
`messages` when lifecycle scripts ran. A lifecycle failure raises `nvyr.config_session.CommitError`; its
`result` attribute contains the complete result, including successful owners.
The normal partial-commit semantics apply: failed owner changes remain pending
in an open session. Other daemon errors raise `nvyr.errors.RouterError` with
`code` and `details`. An expired session raises `SessionExpiredError`, also a
`RouterError`. The library does not print results or errors on the caller's behalf.

## Permissions and lock ownership

Sessions use the caller's authenticated Linux account and current nVyR role.
Dev-admins, sys-admins and net-admins can configure within their existing
role restrictions; read-only users cannot open configuration sessions. Socket access
alone does not grant configuration permission. The library does not silently
take another session's lock or accept a stale candidate; those conditions raise
the daemon's usual errors. Coordinate automation with interactive configuration
work, and close/reopen or discard/rebuild a candidate when appropriate.

For automation that explicitly takes priority over another configuration session:

```python
with ConfigurationSession() as config:
    config.request_lock(force=True)

    config.set('set system host-name router')

    config.commit()
```

Taking the lock does not discard another session's candidate or close its
connection. Existing permissions, active-commit restrictions, commit-confirm
rollback protection and stale-candidate checks remain enforced. `commit()` never
requests the lock automatically.

Lock errors identify the authenticated Linux username and terminal. For SSH
sessions they also include the client IPv4/IPv6 address when available from the
peer process's SSH environment. The address is descriptive metadata, not proof
of identity; missing SSH metadata does not prevent local or automated sessions.

## Interactive session status

In the interactive configuration CLI, `show config-sessions` lists session IDs,
users, terminals, draft status and the commit-lock owner. Each entry has a
`current` boolean; `true` identifies the session issuing the command, even when
several sessions share a username. It works from any `edit` context and is not
available in operational mode.

`show config-status` shows a headerless Presto table with this session's ID and remaining
lifetime, affected candidate sections, whether running differs from the saved
configuration, the commit-confirm deadline (UTC), active commit/check/rollback,
and the lock holder. It works from any edit context. Candidate status compares
the resulting configuration, so changes that cancel one another are not shown
as pending. Status does not refresh the session lifetime.

`release-session-lock` releases the calling session's lock without discarding its
candidate or leaving configuration mode. The caller must hold the lock; drafts,
active commits/checks/rollbacks and pending commit-confirm timers prevent release.
Use `request-session-lock` to acquire it again before committing or saving.

### Commit feedback and interruption

Interactive commits print progress per configuration section and forward
`context.report()` messages as they arrive. The final summary includes elapsed
time, failures and sections that remain pending after partial success. Successful
commit-confirm output includes its UTC confirmation deadline. The Python library
still returns structured results without printing; completed lifecycle results
also include `elapsed` seconds and `deadline` (null without commit-confirm).

The CLI accepts `commit comment "Added WAN firewall rules"` and
`commit-confirm 1 comment "Testing WAN routing"`. Comments are optional.
`show commit-history` lists retained revisions newest first with Revision, Commit,
Date (UTC), User and Comment headers, using tabulate's default table format.
Revision is the offset accepted by compare/rollback; Commit is the permanent ID.
The command works from any edit context. Confirmation preserves the original
comment. No-op or entirely failed commits create no revision; partial successes
record the comment on the revision containing the changes actually applied.

During a CLI `commit` or `commit-confirm` request, Ctrl+C prints `Commit in progress`
and continues waiting for the result. It does not cancel application or discard
the outstanding response. Confirmation prompts remain interruptible. If configd
is unresponsive, investigate its status and logs from another session before
using a service restart as an emergency recovery action.

Ctrl+C during command insertion stops subsequent lines after the current
configuration request finishes. Accepted changes remain in the candidate. The
CLI prints the following, with a blank line between the messages:

```text
Command insertion interrupted. Changes already accepted remain in the candidate.

Use compare to review them before committing.
```

Operational commands retain their existing interruption behavior, including
Ctrl+C for streaming commands.

## Capture and restore configuration

Configure history retention with `set system configuration commit-revisions N`.
The default is 20 retained revisions, including the current one; the minimum is 1.
Commit applies the limit immediately, and `save()` persists the setting for the
next boot. Removing the setting restores 20. Increasing the limit allows future
history to accumulate; it does not recover deleted snapshots. Saved configuration
and commit-confirm recovery are independent of this history limit.

```python
with ConfigurationSession(timeout=1800) as config:
    original = config.get_config()

    try:
        config.set('set interfaces dummy dum123 description "Temporary test"')

        config.commit()

        # Inspect the resulting host configuration here.
    finally:
        config.load(original)

        config.commit()
```

Replacement commits run only the configuration scripts whose owned configuration
changed. An unchanged replacement is a no-op. Empty configured objects and stored
password hashes are preserved; implicit defaults remain implicit.

Snapshots follow the same visibility rules as configuration displays.
Administrators receive stored authentication data, so treat their snapshots as
sensitive. Network administrators do not receive authentication data and cannot
replace or modify login configuration. Use an administrator session for complete
capture/restore when login accounts exist.

A full restore replaces concurrent configuration changes too; use an isolated
test host or coordinate with other operators. Choose a lifetime that covers the
entire operation and restoration. If the session expires, a new session is needed
to restore the snapshot. Restoring configuration does not restore transient state
such as counters or connections. The 64 MiB RPC frame limit applies to snapshots
and loads, including JSON encoding overhead. Each snapshot or load uses one
message; a replacement load is still validated and staged as one operation.

## Total session lifetime

Python sessions default to **300 seconds**. Override this when opening:

```python
with ConfigurationSession(timeout=600) as config:
    config.set('set system host-name router')

    config.commit()
```

`timeout` is a positive finite number of seconds from session creation, measured
using a monotonic clock. Activity never extends it. Configd's normal interactive
default is **8 hours**, configurable with `configd --session-timeout SECONDS`.
The library explicitly supplies its own default. `socket_path` optionally selects
another local configd socket; the default is `/run/nvyr/configd.sock`.

Configd removes expired sessions, candidate mutations and session locks even
while the client remains connected. Operations then fail with a session-expired
error; open a new `ConfigurationSession` to continue. The interactive CLI stays
in configuration mode, displays the expiry and requires `exit` followed by
`configure` to start a new session.

Expiration does not interrupt a commit already applying configuration: that
transaction finishes safely, without restoring the expired candidate. Pending
commit-confirm recovery data and its deadline survive session expiration or
disconnect. New commits remain blocked until confirmation or rollback completes.
An expired session cannot confirm it, but a new authorized normal session can
confirm before the original deadline without first acquiring the commit lock.
Reconnecting does not extend that deadline.
