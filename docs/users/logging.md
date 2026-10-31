# Local logging

For implementation and testing, see the [developer guide](../dev/logging.md).

nVyR keeps separate files for system services, firewall packet logs, named packet
logging groups, and containers. `show log` reads those files directly. A small,
volatile journal remains available for boot and service diagnostics; operational
log commands do not search it.

## Severity and rotation

The default threshold is `info`. A service can override the global threshold.
More severe messages are included automatically: `warn` includes warnings,
errors, critical messages, alerts and emergencies.

```text
set system logging level info
set system logging service bgp level debug
set system logging service ssh level notice

set system logging rotation size 25m count 10
```

Severity values are `emerg`, `alert`, `crit`, `err`, `warn`, `notice`, `info`, and
`debug`. The services are `system`, `kernel`, `authentication`, `configd`,
`netlinkd`, `bgp`, `static`, `zebra`, `ospf`, `dhcp-server`, `dhcpv6-server`,
`ntp`, and `ssh`. A logging threshold does not enable FRR protocol-specific
debugging commands.

Rotation defaults to **25 MiB and 10 archives per file**. Size accepts `k`, `m`,
or `g`, using powers of 1024. Files are checked each minute, so a busy file can
grow beyond the threshold between checks. The same policy applies to services,
firewall groups and containers; there are no per-group rotation overrides.

Logs are stored under `/var/log/nvyr`. Rotated archives use numbered suffixes and
compression; the newest archive remains uncompressed until the next rotation.
Writers reopen their files without restarting routing daemons or containers.

## Service logs

```text
show log system
show log kernel
show log authentication

show log configd
show log netlinkd
show log bgp
show log static
show log zebra
show log ospf

show log ssh
show log ntp
show log dhcp-server
show log dhcpv6-server
```

DHCP instances have separate files for each VRF. Omitting `vrf` selects the
default routing instance. Chrony is one instance, even when bound to a VRF.

```text
show log dhcp-server vrf BLUE
show log dhcpv6-server vrf BLUE follow
```

`show log` by itself displays the general system log. SSH has its own file;
the authentication file contains other authentication events, such as sudo.

## Firewall packet logs

Existing plain `log`, `log level`, and `log flags` settings write kernel packet
messages into the default firewall file. The explicit rule severity is preserved;
the global system threshold does not discard these deliberately configured
packet records.

```text
set firewall ipv4 input filter rule 10 action drop protocol tcp destination-port 23
set firewall ipv4 input filter rule 10 log level warn
```

Select a family, hook, priority, named chain, or individual rule:

```text
show log firewall
show log firewall ipv4
show log firewall ipv4 input
show log firewall ipv4 input filter
show log firewall ipv4 input filter rule 10

show log firewall ipv6 output raw rule 20
show log firewall ipv4 name CUSTOM
show log firewall ipv4 name CUSTOM rule 30 follow
```

Selectors use the generated prefix, such as `[ipv4-INP-filter-10-D]`. Rule 10
does not also match rule 100, IPv6 rule 10, or another hook's rule 10. A chain
view includes its logged default verdict; a specific rule view selects only that
rule. Only packets actually logged by a rule appear.

### Named logging groups

A log group sends packet records through NFLOG to a dedicated file. Its numeric
NFLOG identifier is allocated internally and retained across configuration
changes and restarts.

```text
set firewall group log-group WAN_DROPS description "Unwanted WAN traffic"

set firewall group log-group WAN_DROPS snaplen 128 queue-threshold 1

set firewall ipv4 input filter rule 10 action drop inbound-interface eth1
set firewall ipv4 input filter rule 10 log group WAN_DROPS
```

```text
show log firewall group WAN_DROPS
show log firewall group WAN_DROPS follow

show log firewall ipv4 input filter rule 10
```

The last command searches default and named packet log files using the rule's
prefix. It still finds records after a rule is moved to a different logging
group. The group remains reusable by multiple rules and both address families.

`snaplen` controls how many packet bytes are copied, from 1 through 65535
(default 65535). `queue-threshold` controls batching, from 1 through 65535
(default 1). Larger batches can delay log delivery. A small snaplen can omit
packet details beyond the copied bytes.

NFLOG group logging cannot be combined with `log level` or `log flags`: those
options control kernel text logging. Referenced groups cannot be deleted until
their references are removed. Fail-safe log groups use independent identifiers
and files; their collectors are ready before temporary rules are activated.

### NAT logs

NAT uses the same logging statements and packet files, with source/destination
prefixes that remain distinct from filter and raw rules.

```text
show log nat
show log nat source
show log nat source rule 10

show log nat destination rule 20 follow
```

## Container logs

Container output uses Podman's `k8s-file` driver. It preserves stdout/stderr
records after the workload exits. A separate service file captures launch
errors, including failures before Podman creates the container.

```text
show log container DNS
show log container DNS follow
```

The display shows only the container application's stdout/stderr, including during
`follow`. Host service messages remain in the separate service file; use
`show system services container name DNS` to inspect startup status and failures.
Application output has no standard
severity field, so system severity thresholds do not filter it.

## Paging and following

Commands show the complete current file contents that match the selector;
numbered archives remain on disk. There is no `lines` option or implicit tail
limit. Use the normal output controls:

```text
show log bgp | more
show log firewall ipv4 input filter rule 10 | no-more
```

Append `follow` to display existing matching records and continue streaming new
ones. Ctrl-C ends the stream. Following survives file rotation and waits for
files that have not received their first record yet.
