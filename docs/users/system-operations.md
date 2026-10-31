# System settings and operations

For implementation and testing, see the [developer guide](../dev/system-operations.md).

## Hostname and revision retention

Configure the router's hostname and the number of retained commit revisions:

```text
set system host-name edge1
set system configuration commit-revisions 20

commit
save
```

`host-name` accepts 1–15 characters, beginning with a letter, followed by letters,
digits, underscores, dots or hyphens. Commit updates the live hostname,
`/etc/hostname`, and the `127.0.1.1` entry in `/etc/hosts`, so local hostname
resolution does not depend on external DNS. Removing it restores `nvyr`.

Revision retention defaults to 20 and includes the current revision. Use
`show commit-history` in configuration mode to inspect retained revisions.
For other system settings, see [users and roles](login.md), [DNS](dns.md),
[NTP](ntp.md), and [SSH](ssh.md).

## Time zone

Choose a local time zone from the installed IANA timezone database. Tab completion
and `?` offer available names, including `UTC`:

```text
set system time-zone America/New_York

commit
save
```

Invalid names receive a spelling suggestion when there is a close match. For
example, `america/new-york` suggests `America/New_York`. Enter the suggested
spelling yourself; nVyR does not automatically change the value.

Inspect the current local date, time, and timezone abbreviation:

```text
show date
```

Use `run show date` in configuration mode. Regional zones follow their daylight
saving rules automatically. For example, New York displays EST in winter and EDT
in summer. The default is UTC; deleting `system time-zone` restores UTC.

This setting changes local-time presentation and schedules that use the router's
timezone, such as the GeoIP midnight update. It does not change the system clock,
the hardware clock, or NTP synchronization. Displays explicitly labelled UTC
continue to show UTC. Container workloads retain their own timezone settings;
operational commands from an isolated CLI session report the host's time.

## CPU frequency and energy policy

nVyR selects the `performance` governor at boot where the CPU driver supports it.
Policies without that governor retain their existing setting; VMs that expose no
CPU frequency controls require no special configuration. This is runtime boot
initialization, not an implicit value added to the configuration tree.

Override the governor for every CPU policy:

```text
set system cpu governor performance

commit
save
```

Available governor names are `performance`, `powersave`, `schedutil`, `ondemand`
and `conservative`, limited to those advertised by every CPU policy on this host.
Completion includes descriptions. Explicit unsupported settings are rejected.
Intel active `powersave` adjusts frequency dynamically; the generic governor of
the same name requests the lowest allowed frequency.

On hardware with energy-performance preferences, select a dynamic governor and
then its desired balance. For example, on Intel active P-state hardware:

```text
set system cpu governor powersave
set system cpu energy-performance balance-performance

commit
save
```

Preferences are `performance`, `balance-performance`, `balance-power`, `power`
and `default`, again restricted to values advertised by every policy. `default`
selects the platform preference. Intel active P-state and AMD EPP performance
governors require preference `performance` or no explicit preference.

Removing `energy-performance` restores the pre-management preference when the
selected governor permits it. Removing the governor override returns to the boot
policy: performance where supported, otherwise the original native governor.
Settings are reapplied during configuration recovery; `save` persists explicit
overrides across reboots. Failed writes restore the previous policy settings.

```text
delete system cpu

commit
save
```

`show system cpu` reports the actual frequency driver, governor and energy
preference. Unsupported controls appear as `Not exposed`. AMD driver behavior
has simulated test coverage; AMD hardware validation remains outstanding.

## Basic information

```text
show version
show license

show date
show system uptime

show system cpu
show system cpu usage
show system memory
```

`show version` reports the nVyR version, UTC image build date, builder attribution,
copyright and project repository URL in a headerless table. An omitted builder is
shown as `Not specified`. `show license` prints the complete installed MIT license
through the normal pager.

`show date` and `show system uptime` display the system date and native uptime/load summary.
The CPU summary reports model, architecture, sockets, cores, threads, online
CPUs, detected virtualization and current CPU frequency policies. `cpu usage` samples one second and displays
aggregate and per-CPU user, system, I/O-wait, steal and idle percentages.
`show system memory` uses the human-readable `free` summary, including swap.

For storage, process and diagnostic-bundle commands, see
[system diagnostics](system-diagnostics.md). For VRF inventory, see
[interface diagnostics](interface-operations.md#vrf-inventory).

## Configuration script priorities

```text
show system config script-priority
```

Displays Script, Priority and Paths columns, sorted by priority and then script
name. Each script appears once, with its declaring paths on separate lines.
`<name>` represents a tag instance. Only paths that explicitly declare the script
are listed; children inheriting ownership are omitted.

The inventory is generated from the expanded configuration schema during the
build and shipped with the router. It describes all registered scripts, regardless
of the current configuration, rather than the execution plan for a pending commit.
The command is available to all roles, including through `run` in configuration mode.

## Package inventory

```text
show system packages
show system packages frr

show system packages | match nftables
show system packages | no-more
```

The table lists package names, versions, architectures and descriptions from
`dpkg-query`, sorted by package name. The optional selector matches an exact
package name. Tab completion offers package names with their descriptions,
including architecture qualifiers such as `libc6:amd64` when present.
These read-only commands are available to all roles and through `run` in
configuration mode.

## Users and service health

These read-only commands are available to operators, net-admins and
administrators. They also work through `run` in configuration mode.

```text
show users

show system services
show system services configd
show system services configd detail

show system services dhcp-server
show system services dhcp-server vrf BLUE
show system services dhcpv6-server vrf default

show system services container
show system services container name DNS
show system services container vrf BLUE
```

Service selectors are `configd`, `netlinkd`, `frr`, `ssh`, `ntp`, `dhcp-server`,
`dhcpv6-server` and `container`. Each supports `detail`. Services with routing
instances support `vrf <name>`; containers also support `name <name>`.
Instance selections use the headerless `presto` detail layout. Summary views use
the standard headered table format.

### Login sessions

`show users` reports active terminal logins, not configuration sessions or login
history. Each terminal gets a row, even when multiple sessions share a username.
The calling terminal's username is marked `(this session)`, including when run
from configuration mode. Non-terminal API calls do not mark another user's session.
The source is the address recorded by SSH, or Console/Local for a local terminal.
No reverse DNS lookup is requested. Login time is in the router's timezone, at
the minute precision supplied by `who`; idle time comes from the terminal's last
access time. An unavailable terminal has unknown idle time, shown as an em dash.
Non-interactive SSH commands without a terminal are not terminal logins.

Missing login accounting is reported as an error, rather than an empty user list.

### Service state

The summary includes the three core daemons and configured optional services,
including stopped and disabled instances. A configured service with no installed
unit is reported as Missing. Selecting an absent service returns an empty-instance
message; selecting an absent VRF or container instance reports an error.

Process state comes from systemd. Uptime measures the current process lifetime
using a monotonic clock. Restarts is systemd's automatic-restart counter, not a
lifetime count: manual stop/start and `reset-failed` can reset it. Exit status or
terminating signal is shown when reported by systemd.

Kea additionally reports listener readiness through its control socket. Only a
reported link-down retry with matching interface state becomes Waiting for
carrier. Other listener errors become Not ready. Chrony reports synchronization
separately from whether its process is running. A failed health query is shown as
Health unavailable; it is never interpreted as healthy.

The VRF column for a container lists the VRFs of its attached networks. A host
network container shows default; an isolated container has no network VRF.
This column does not imply that the container process itself runs in a Linux VRF.

No restart, log retrieval or configuration mutation is performed. Core service
Running means the supervised process is active, not an exhaustive application
health check (for example, it does not certify every FRR child daemon).
