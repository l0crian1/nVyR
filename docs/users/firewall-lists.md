# Firewall groups from lists and CSV files

Attach one or more files to a group to keep external policy in a single lookup.
Address, interface, MAC and port groups use `from-list`; match-groups and maps
use `from-csv`. Ordinary rule references stay the same.

## Address lists

Each nonempty line contains one value. Blank lines and lines beginning with `#`
are ignored. Addresses must be literal addresses, prefixes or supported ranges;
hostnames are skipped rather than resolved.

```text
192.0.2.10
198.51.100.0/24
```

```text
set firewall group address-group ipv4 THREATS from-list BLOCKLIST source https://example.net/blocked.txt
set firewall group address-group ipv4 THREATS from-list BLOCKLIST interval 6h
set firewall group address-group ipv4 THREATS from-list LOCAL source /config/lists/blocked.txt
set firewall ipv4 input filter rule 100 source-address-group THREATS action drop
```

The same attachment syntax works under IPv6 address groups, `interface-group`,
`mac-group` and `port-group`. Files use the same value syntax as those groups'
manual members. An interface list can contain native interface wildcard patterns.

## CSV match-groups and maps

Select the group's match fields, then map each field to its column number,
starting at 1. `column` is anchored, so several mappings can share one command.
The column order does not need to match the CLI's field order. Extra columns are
ignored. Quoted fields may contain commas; each entry must occupy one line.
There is no header-name mapping: a header that does not contain valid values is
reported and skipped like any other invalid row.

For this CSV:

```csv
192.0.2.10,198.51.100.20,443,tcp
192.0.2.11,198.51.100.21,53,udp
```

```text
set firewall group match-group ipv4 THREATS match source-address destination-address destination-port protocol
set firewall group match-group ipv4 THREATS from-csv FEED source /config/lists/tuples.csv
set firewall group match-group ipv4 THREATS from-csv FEED column source-address 1 destination-address 2 destination-port 3 protocol 4
set firewall ipv4 forward filter rule 100 match-group THREATS action drop
```

A map also maps its result columns. The configured `result-type` determines which
result fields are required:

```csv
192.0.2.10,198.51.100.20,443,tcp,drop
192.0.2.11,198.51.100.21,53,udp,accept
```

```text
set firewall group map ipv4 POLICY match source-address destination-address destination-port protocol
set firewall group map ipv4 POLICY result-type verdict
set firewall group map ipv4 POLICY default-result action continue
set firewall group map ipv4 POLICY from-csv FEED source /config/lists/policy.csv
set firewall group map ipv4 POLICY from-csv FEED column source-address 1 destination-address 2 destination-port 3 protocol 4 result action 5
set firewall ipv4 forward filter rule 100 map POLICY
```

Use `column result address`, `column result port`, or both for NAT maps. A verdict
CSV can also map `column result jump-target`; leave that cell empty on non-jump
rows. Targets must be configured named chains in the same family, and the normal
hook restrictions still apply. IPv4, IPv6 and inet maps/match-groups retain their
existing supported fields and result types.

## Sources and updates

Sources may be absolute local filenames or HTTP, HTTPS, FTP, FTPS or TFTP URLs.
Local files are not restricted to `/config`, but files elsewhere are not
automatically copied to a new system image. `/config/lists/` is a useful location
for persistent input files. HTTPS and FTPS use normal certificate verification.

Remote retrieval allows two seconds for connection establishment, including DNS,
and five seconds for the complete transfer, with a six-second process deadline.
Up to ten attachments download concurrently, without automatic retries. Ten
unreachable sources therefore do not incur ten sequential connection timeouts.

The first commit retrieves each new or changed attachment. Later commits reuse
compatible cached content. To fetch again manually:

```text
update firewall group address-group ipv4 THREATS
update firewall group address-group ipv4 THREATS from-list BLOCKLIST
update firewall group map ipv4 POLICY from-csv FEED
```

An attachment may have an `interval`, or a `calendar` with `at`, `day-of-week`
and `day-of-month`. These use the same scheduling syntax as system tasks:

```text
set firewall group map ipv4 POLICY from-csv FEED calendar at 03:30
set firewall group map ipv4 POLICY from-csv FEED calendar day-of-week weekdays
```

An interval runs between one execution finishing and the next starting. Without
a schedule, updates are manual. A refresh hashes downloaded content before
parsing; unchanged files do not cause native membership replacement. Updates
replace set/map elements atomically and do not rebuild the consuming rules.

## Invalid entries and source comments

Invalid rows are skipped with warnings; valid rows still load. An unavailable
source uses its compatible cache, or contributes no members if none exists.
One unavailable feed does not prevent the firewall from being configured.

Equivalent complete keys are deduplicated. If a map key has different results,
every occurrence of that key is excluded, including occurrences in other
attachments. The warning identifies the key and conflicting results. Different
complete keys in concatenated maps remain distinct even when ranges intersect.
Single-field maps cannot represent overlapping ranges: all entries involved in
an overlap are excluded with warnings, including when their results agree.

Each element has an origin comment such as `BLOCKLIST` or `BLOCKLIST, LOCAL`.
Combined comments longer than nftables' 128-byte limit end in `...`.
Native auto-merge remains enabled for interval sets that support it. **Merging
adjacent or overlapping ranges can retain only one of their comments**, so the
listed comment may not name every contributing source. Concatenated interval
groups use the native backend without auto-merge.

Imported groups cannot also contain manual entries, GeoIP membership or
`include-group`, and cannot be included in another group. Dynamic address groups
and match-groups may use imports with exact keys. A changed-file refresh replaces
their membership, including any packet-learned entries. An unchanged-file refresh
leaves learned entries alone. Imported members use the dynamic group's timeout
and size limit too. An unchanged-file refresh does not reinsert imported members
that have expired; they return when changed content is loaded or the group is
rebuilt by a configuration change/recovery.

## Logs, caching and rollback

```text
show log firewall lists
show log firewall lists | match THREATS
show log firewall lists follow
```

Manual and scheduled updates log download outcomes, invalid rows, ambiguous keys,
counts and elapsed retrieval/parsing time. The dedicated `firewall-lists` service
uses nVyR's existing logging and rotation configuration.

Cache files live under `/config/firewall/lists/` and transfer with the image's
persistent configuration. Failed commits and commit-confirm expiry restore the
previous imported content without fetching the sources again. A scheduled or
manual refresh is a runtime update, not a configuration revision; it has no
separate rollback history.
