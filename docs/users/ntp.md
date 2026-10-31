# NTP

For implementation and testing, see the [developer guide](../dev/ntp.md).

nVyR uses one Chrony process to synchronize the system clock and optionally serve
time to clients. It uses the default routing domain unless a VRF is selected.

## Configuration

```text
set system ntp server 192.0.2.10 prefer
set system ntp server time.example.net nts
set system ntp pool pool.ntp.org

set system ntp listen-address ipv4 192.0.2.1
set system ntp listen-address ipv6 2001:db8::1

set system ntp allow-client 192.0.2.0/24
set system ntp allow-client 2001:db8::/64

set system ntp vrf MANAGEMENT
```

`server` uses one source per entry. `pool` discovers multiple sources through DNS;
Chrony's default target is four responding sources. Both enable `iburst`. `nts`
requires a source supporting Network Time Security and a trusted certificate.
`prefer` favors a suitable individual server; it does not force acceptance of
an incorrect time source. There are no implicit public upstream servers.

`listen-address` contains singleton `ipv4` and `ipv6` leaves. Reconfiguring a leaf
replaces its previous value. An omitted family uses Chrony's wildcard listener
for that family. Explicit non-wildcard addresses must belong to the chosen VRF.
Configuring addresses alone does not authorize clients: `allow-client` supplies
the permitted addresses/networks. With no allowed clients, Chrony operates only
as a client. Existing firewall policy still applies to NTP traffic.

`vrf` applies to the whole service: NTP, NTS key exchange, and DNS resolution run
inside that VRF. The VRF must exist, and dependency checks prevent its deletion
while NTP references it. DNS servers must be reachable through the chosen VRF.
Interface changes trigger verification again. `commit check` skips live listener
address checks because the candidate interfaces have not been applied yet.

## Synchronization and source inspection

Unreachable sources or unavailable DNS do not block commit or boot. Chrony retries
asynchronously. `show ntp` reports synchronization state; `show ntp sources`
shows source selection, reachability, offsets and unresolved sources. Use
`show ntp sources no-resolve` to display individual source IP addresses instead
of configured names, making pool members distinguishable.

## Client activity and server statistics

Serving activity is available separately from upstream synchronization:

```text
show ntp clients

show ntp server statistics
show ntp server statistics detail
```

`clients` shows numeric client IPs, requests received, requests rate-limited,
the observed average request interval in seconds, and seconds since the last
request. Unknown times appear as an em dash. Only clients with NTP requests are
shown; command-only visitors are omitted. Chrony records clients allowed by its
access rules, subject to its client-log memory limit. This is not a log of blocked
attempts or proof that clients have synchronized successfully.

`server statistics` shows received and rate-limited NTP requests, authenticated
and interleaved requests, and client records dropped because the client log is
full. `detail` includes all management, NTS and timestamping statistics. Some of
these remain zero when their corresponding features are unused. These commands
do not reset counters; restarting Chrony clears its activity history.

## Clock changes and persistence

NTP can step the clock during initial synchronization after boot. Later
configuration changes preserve gradual correction. Drift data and NTS cookies
are retained under `/config/ntp/`; deleting `system ntp` stops the service but
retains that data. No UDP management port is opened.
