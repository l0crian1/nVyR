# Using the CLI

For implementation and testing, see the [developer guide](../dev/cli.md).

nVyR separates configuration from live operational commands. In operational mode,
`show interfaces` inspects the router. After `configure`, `show` displays
configuration and `run show interfaces` inspects the live interfaces.

## Configure, check, commit and save

`set` and `delete` change your session's candidate. They do not immediately change
the router. `commit` applies changes; `save` persists the running configuration
for the next boot.

Deleting a node or multi-value member that is absent from the candidate prints
`Nothing to delete: <path> is not configured.` The command still succeeds and
adds no pending change. This includes values already deleted in the current
session. Invalid paths, invalid values, and a supplied value that differs from
an existing single-value setting remain errors.

```text
configure

set interfaces dummy dum0 description "Test interface"
set interfaces dummy dum0 address 192.0.2.1/32

compare
commit check

commit comment "Add test interface"
save
exit
```

`commit check` verifies without applying. Checks that depend on unapplied live
state can be deferred with a message and still run during the actual commit.
Independent configuration units can commit separately: if one fails, inspect the
summary and `compare` to see what remains pending. `discard` removes pending
changes; it does not undo an already successful commit.

During commit, Ctrl+C reports `Commit in progress` and keeps waiting. Interrupting
multiline command insertion stops subsequent commands, while changes already
accepted remain in the candidate.

## Help, completion and command history

Use `?` for possible completions and Tab to complete a keyword or value. Hints
appear in angle brackets above choices and suggestions in each context. Unique
keyword abbreviations are accepted; quote values containing spaces.

Each completion listing prints the current prompt and command above it, so
repeated help requests retain their context in the terminal scrollback. The
active command remains editable below the listing.

Anchored objects allow several settings in one command:

```text
set firewall ipv4 input filter rule 10 action accept protocol tcp destination-port 22 counter
```

Completed single-value settings disappear from suggestions for that line. Multi
settings remain available. Nested help lists outer parameters first and the
current context last, closest to the prompt. For eligible fields, `not` negates
a value and `and` joins components while retaining completion:

```text
set firewall ipv4 input filter rule 10 source-address not 192.0.2.10
set firewall ipv4 input filter rule 10 tcp-flags syn and not ack
```

Up/Down navigate separate operational and configuration histories. Consecutive
identical commands occupy one history entry; repeating a command after a different
command keeps the new entry. History does not drive inline schema suggestions.

## Edit a section

`edit` makes configuration paths relative to a section or named instance. `up`
moves to its parent and `top` returns to the root.

```text
edit firewall ipv4 input filter

set rule 20 action accept protocol icmp

delete rule 20

up
top
```

Operational commands entered through `run` always use their normal root paths.

## Display configuration and defaults

- `show`: running configuration with this session's pending changes marked.
- `show running-configuration`: explicit settings currently applied.
- `show candidate-configuration`: pending changes only.
- `show all`: complete effective candidate, including applicable defaults.
- `show running-configuration all`: effective running configuration.
- `show candidate-configuration all`: complete effective contents of changed
  top-level sections, retaining deletion markers for removed sections.

Add a configuration path to narrow the display. Put `all` before that path:

```text
show running-configuration interfaces
show running-configuration all interfaces
show candidate-configuration all firewall
show firewall | commands
```

`| commands` renders configuration as CLI commands. In scoped displays, paths are
relative to the selected section. Use a root-level display for a complete export.
Showing defaults does not configure them; importing an export containing defaults
makes them explicit.

## Copy, rename and inspect references

Copy and rename operate on instances of the same tag node. Both paths name the
object, including its tag keyword; the destination must not exist.

```text
edit firewall ipv4 input filter

copy rule 10 to rule 20
rename rule 20 to rule 30

top

show references interfaces dummy dum0
```

Copies include explicit candidate settings and are independent afterward. These
commands do not copy a rule between different hooks or rewrite references.
Some tag nodes, such as VRFs, prohibit renaming. Reference inspection requires a
tag instance that registers dependencies and examines running configuration plus
your pending changes. Remove its references before deleting a referenced object.

## Confirmed commits and revision history

Use a confirmed commit when testing a change whose continued operation you need
to verify. The CLI timeout is in minutes:

```text
commit-confirm 5 comment "Test new routing policy"

run show ip route

confirm
save
```

If the deadline expires without confirmation, nVyR restores the earlier
configuration. Closing the session does not cancel that deadline.

To verify that a firewall change still permits a new login, disconnect and log
back in before the deadline, then run:

```text
configure
confirm
```

Any administrator with configuration access can confirm; `request-session-lock`
is not required. Confirmation does not apply candidate edits, save configuration,
or acquire the lock. Reconnecting does not extend the rollback deadline.

### Delayed commits

Use `delay` to coordinate changes on routers that depend on each other:

```text
commit delay 0.5
```

This verifies and freezes the current candidate, then starts its commit after
30 seconds. Both delay and confirmation timeouts accept decimal minutes greater
than zero and at most 1440. To delay for 15 seconds and allow two minutes to
confirm after application finishes:

```text
commit-confirm 2 delay 0.25 comment "Coordinated routing change"
```

The schedule survives logout and configuration-session expiry. Later candidate
edits do not change it. Other commits, saving and lock transfers remain blocked
until execution or cancellation. The frozen candidate is verified again before
application; results appear in session notifications and configd's log.

```text
show config-status

cancel
```

`cancel` cancels a scheduled commit that has not started, without discarding
candidate edits. An authorized administrator can reconnect, enter `configure`,
and run `cancel` or, after a commit-confirm has completed, `confirm`, without
first acquiring the lock. Cancellation cannot interrupt application and does
not cancel an active confirmation timer.

Restarting configd or rebooting cancels an unexecuted schedule and logs the
cancellation. A schedule does not save configuration. Execution starts when the
delay expires and configd is idle; relative delays are not exact synchronization
between routers.

### Revision history

```text
show commit-history
compare 1

rollback 1

compare

commit
```

History's Revision column is the offset used by `compare` and `rollback`; Commit
is the permanent identifier. Rollback stages a revision and still needs commit.
`compare` compares pending changes with running configuration; `compare saved`
compares running with saved configuration.

## Sessions and locks

```text
show config-status
show config-sessions

request-session-lock
release-session-lock
```

The lock controls commits and saves, while each session retains its own candidate.
Taking a lock held by someone else requires confirmation; releasing it does not
discard your changes. An active commit or pending confirmed commit restricts lock
transfer. `show config-status` reports the holder, remaining session lifetime,
pending changes and whether running configuration is saved.

From operational mode, `configure draft` opens a non-committing candidate for
inspection and preparation. Drafts cannot acquire the commit lock, commit or save.
Expired sessions must be closed and reopened. See [configuration sessions](../dev/config-session.md)
for automation and lifetime details, and [roles](login.md) for access restrictions.

## Import and export

From the configuration root, export applied settings to a file:

```text
top

show running-configuration | commands | export /tmp/router.set
show running-configuration | export /tmp/router.json
```

Load JSON or a file of set commands, then inspect and commit:

```text
load /tmp/router.json
load set /tmp/router.set

compare
```

These merge by default. `load replace /tmp/router.json` and
`load replace set /tmp/router.set` stage replacement configuration. File paths are
local to the CLI process, and loaded set paths are absolute even inside `edit`.
Set imports report errors by line; always review those errors and the resulting
candidate before committing. Neither import format applies or saves automatically.

## Output filters and paging

```text
run show interfaces | match eth
run show ip route | except '^C' | count
show running-configuration | strip-private | commands
run show firewall | no-more
```

`match` keeps lines matching a regular expression; `except` removes them. Quote
expressions containing spaces or `|`. `count` counts output lines.
`strip-private` masks sensitive values in configuration output and operational
commands that support it. Apply `commands` before text filters if command-form output is
needed; text filters discard configuration structure.

Choose how much to mask:

- `strip-private` or `strip-private all`: fully mask designated private values.
- `strip-private partial`: retain the first two IPv4 octets or IPv6 hextets and
  the first three MAC octets. Prefix lengths remain visible. Other private text,
  including descriptions, stays fully masked.
- `strip-private public`: mask globally routable unicast IP addresses. Non-public
  addresses, MACs, names, and descriptions remain visible. This uses address
  classification, not just an RFC1918 check.

Credentials remain fully masked in every mode. Partial output deliberately reveals
part of your addressing; review output before sharing. Configuration displays add
unique aliases to masked values so distinct entries and changes remain distinguishable.
These choices affect display only and do not modify configuration.

### Paging command output

Long captured output pages automatically in an interactive terminal. Short output
prints without waiting for input. Use `| more` to explicitly request paging or
`| no-more` to print the complete result directly:

```text
show running-configuration | commands | more
show ip route | match '^S' | more
show running-configuration | no-more
```

Use `set terminal length 20` in operational mode to display 20 output lines per
page, or `set terminal length 0` to disable automatic paging. The setting applies
only to this CLI session, including its configuration-mode output; use
`run set terminal length 20` to change it from configuration mode. New sessions
use the terminal height automatically. An explicit `| more` overrides length 0
using the terminal height, and `| no-more` always bypasses paging.

Both modifiers must be last, like `export`. They work in operational and
configuration mode, including `show`, `compare`, and `run`. In the pager, Space
advances a screen, arrow keys scroll, `/pattern` searches, `n` repeats a search,
and `q` or Ctrl+C returns to the CLI early. Reaching the final page automatically
returns to the CLI, leaving the output visible. Resizing the terminal adjusts the display
unless an explicit terminal length has been set.
Paging uses [less](https://manpages.debian.org/trixie/less/less.1.en.html) in secure
mode with shell escapes, file browsing, custom configuration, and history disabled.

Quitting the pager leaves the completed command intact. Exports and noninteractive
output are not paged. Commit feedback and streaming commands stay live.

### Regular-expression output filters

`| match <expression>` keeps lines where the regular expression finds a match;
`| except <expression>` removes those lines. Expressions support groups,
alternation, anchors, character classes and quantifiers. Filters can be chained:

```text
show ip route | match "(0.0.0.0|10.0.101)"
show ip route | except "(0.0.0.0|10.0.101)"
show ip route | match 10.0.101 | except "\.12/"
```

Quote expressions containing spaces or `|` so they remain a single argument.
Single quotes preserve every backslash; double quotes preserve regex escapes
such as `\.` and `\d`, while `\"` and `\\` escape a quote or backslash. Matching
uses line contents without their newline terminators and preserves original output
line endings. Escape regex metacharacters when literal matching is intended.
Invalid expressions report a CLI error before the underlying command executes.

## Host commands for dev-admins

Only dev-admin users can execute host commands through `shellcmd`:

```text
shellcmd ip -brief address
shellcmd vtysh -c "show ip route"
run shellcmd vtysh -c "show ipv6 route"
```

This works from operational or configuration mode, including an edit context.
Commands run as root. There is no implicit shell expansion; use an explicit shell
when you need shell syntax. Sys-admin, net-admin, and read-only roles cannot use
this command. Use `shell` for an interactive Linux shell from a dev-admin session.
