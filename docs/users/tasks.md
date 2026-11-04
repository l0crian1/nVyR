# Scheduled tasks

Use `system task <name>` to run a command at an interval or at specific local times. A task has one action and one schedule. Commit to arm it; save to restore it after reboot.

To refresh GeoIP every Sunday at 03:00:

```text
set system task REFRESH-GEOIP op-command 'update firewall geoip'

set system task REFRESH-GEOIP calendar day-of-week sunday
set system task REFRESH-GEOIP calendar at 03:00
```

This example adds a refresh alongside the [built-in daily GeoIP update](firewall-geoip.md#updates-and-status).

An `op-command` uses operational syntax and tab completion. Use a captured display such as `show interfaces`, or a command explicitly available unattended, such as `lookup example.com`, `update firewall geoip` or `update firewall domain-group`. Commands that prompt, open a shell, follow a live stream, or need output pipes aren't available as scheduled operational commands.

To run a script every six hours:

```text
set system task BACKUP exec '/config/scripts/backup.sh'

set system task BACKUP interval 6h
```

**Sys-admin and dev-admin can configure both actions.** An `exec` command runs as root on the host using `/bin/sh -c`; pipes and redirection work. Net-admin can configure, start, and read output from operational tasks. Only sys-admin and dev-admin can do those things for a shell task.

Intervals accept a positive number followed by `s`, `m`, `h`, or `d`, up to 365 days. The first run is one interval after the timer is armed; subsequent runs wait one interval after the previous run finishes. A calendar uses the router's time zone. Missed runs during downtime aren't replayed.

To run at two times, on the first or last day of the month, but only if that day is a weekday:

```text
set system task REPORT op-command 'show uptime'

set system task REPORT calendar at 06:30
set system task REPORT calendar at 18:00

set system task REPORT calendar day-of-week weekdays
set system task REPORT calendar day-of-month 1
set system task REPORT calendar day-of-month last
```

Repeat any calendar field to add another value. Day names are `monday` through `sunday`; `weekdays` means Monday–Friday and `weekends` means Saturday–Sunday. Omit both day filters to run every day.

```text
show system tasks
show system tasks REPORT

start system task REPORT
show log task REPORT
```

The status shows the next run, last start, and result. A manual start returns immediately. Starting a running task does not launch a second copy. Output and errors go into the same task log and follow the system log rotation settings.

To pause a task, set `system task REPORT disable` and commit. This prevents scheduled and manual starts; an already running command may finish. Delete `disable` and commit to resume.
