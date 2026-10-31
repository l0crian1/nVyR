# System settings and operations: implementation and maintenance

For configuration and command usage, see the [user guide](../users/system-operations.md).

## Timezone configuration

`system_timezone.py` owns `system time-zone` at priority 0, before logging
and networking configuration scripts. The schema supplies the always-mode UTC default
within `system`; the script also resets UTC when the entire `system` branch is
absent, including initial recovery. `tzdata` is an explicit image/package dependency.

The validator checks an installed TZif file beneath `/usr/share/zoneinfo`, rejecting
path traversal, external symlinks, and the special `posix/`, `right/`, `localtime`,
and `posixrules` entries. Suggestions use Python's IANA inventory filtered against
the installed host files. Neither inventory nor validation caches names across
timezone database updates.

The normal four-stage script gathers the zone and current file snapshots, prepares
the desired `/etc/localtime` symlink and `/etc/timezone` text, and atomically replaces
each file during apply. It never writes through a zoneinfo symlink. On failure it
restores both previous files, preserving symlinks or copied timezone files, and
reports failed compensation distinctly. `time.tzset()` refreshes configd's process
timezone after apply and compensation. No clock-setting command or NTP restart is
involved. See [systemd's localtime contract](https://www.freedesktop.org/software/systemd/man/latest/localtime.html).

`tests/test_timezone.py` covers names, completion, UTC defaults, read-only
preparation, file replacement, compensation, and saved-state recovery.
`smoketests/test_timezone.py` checks installed configuration and date output,
including fractional offsets and invalid names. The acceptance configuration uses
`America/New_York`; `check_system_timezone` inspects both native files and
`show date` before and after reboot.

## Testing

```text
python -m pytest tests/test_service_health_op.py tests/test_system_op.py tests/test_timezone.py
sudo python3 /usr/lib/nvyr/functionaltests/test_system_operations.py
```

## Structured operational output

Operational Python entry points support `raw=True`/`--raw` for JSON consumers.
There is no public JSON keyword in the CLI tree.

## Login accounting

The package creates `/run/utmp` through systemd-tmpfiles so SSH and console logins
can record active sessions. This file is recreated at boot and never truncated
by package upgrades. On a router that previously lacked it, reconnect existing
sessions after installing the package; existing processes cannot retroactively
register their earlier login. Missing accounting is reported as an error rather
than incorrectly claiming there are no users.
