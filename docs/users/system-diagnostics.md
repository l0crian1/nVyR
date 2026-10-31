# System diagnostics

For implementation and testing, see the [developer guide](../dev/system-diagnostics.md).

Inspect resource pressure or collect a bounded snapshot for troubleshooting.
These commands complement the [system and service summaries](system-operations.md).

## Storage and processes

```text
show system storage

show system processes
show system processes cpu
show system processes memory

generate system diagnostics
```

Storage displays filesystem space and inode usage together, including overlay
filesystems used by live images. Unsupported statistics display as `—`.
Processes show executable names without their arguments. CPU percentages are
`ps` lifetime averages; use `show system cpu usage` for sampled CPU utilization.
The default process order is PID; `cpu` and `memory` sort descending.

## Diagnostic snapshot

`generate system diagnostics` is available to net-admins and administrators.
It writes a unique `.tar.gz` archive under `/config/diagnostics/` and prints the
path. Archives are root-readable only (mode 0600); use a root shell or `sudo` to
retrieve them. Existing archives are retained until explicitly removed.

Collection includes version/build, kernel, uptime, installed images, CPU, memory,
storage, processes, managed-service health, failed units, links, addresses,
IPv4/IPv6 routes and routing rules, VRFs, containers (including stopped ones),
and container networks. It does not collect logs, configuration files,
environment variables, full process arguments, or full container inspections.
The archive still contains operational information such as addresses and names.

### Collection bounds and failures

Collection allows up to 10 seconds and 1 MiB per report, with 60 seconds and
8 MiB of report output overall. The complete operation has a 75-second deadline.

Each report has its own text file. `manifest.json` records its command, status,
elapsed time, captured byte count and exit code where available. Status is `ok`,
`error`, `timed-out`, `truncated`, or `skipped`. Missing tools and individual
failures preserve the other reports; output and time budget exhaustion skip
remaining reports. The final message states how many reports are incomplete.
An archive is published only after it is complete; an interrupted run may leave
a hidden `.partial` file if the service was forcibly killed.
