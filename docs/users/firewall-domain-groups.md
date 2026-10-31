# Domain groups

Domain groups resolve exact DNS names into IPv4 or IPv6 address sets. Rules match
those IP addresses; they do not inspect HTTP hostnames or TLS names. A domain does
not include its subdomains, and shared hosting addresses match all traffic to that IP.

## Configuration

```text
set firewall group domain-group ipv4 SERVICES description "External services"
set firewall group domain-group ipv4 SERVICES counter
set firewall group domain-group ipv4 SERVICES last-used

set firewall group domain-group ipv4 SERVICES domain api.example.com
set firewall group domain-group ipv4 SERVICES domain updates.example.com
set firewall group domain-group ipv4 SERVICES lookup rounds 5

set firewall ipv4 forward filter rule 100 action accept destination-domain-group SERVICES
```

IPv4 groups query A records; IPv6 groups query AAAA records. CNAMEs are followed.
Each successful response contributes all returned addresses. `lookup rounds` accepts
1–100, default 1, and performs back-to-back queries without an interval. Duplicate
answers do not end the rounds early. A caching DNS server can return identical
answers, so additional rounds cannot guarantee discovering every possible address.

```text
set firewall group domain-group ipv6 SERVICES domain api.example.com

set firewall ipv6 forward filter rule 100 action accept destination-domain-group SERVICES
set firewall ipv6 forward filter rule 110 action drop source-domain-group not SERVICES
```

Source and destination references work in firewall rules, including named chains and
raw hooks, and IPv4 NAT rules. A reference cannot duplicate the same packet field
from an explicit positive match, another positive singleton group, a map, or a
match-group. Positive and negative matches remain separate.

## Inclusion and tracking

```text
set firewall group domain-group ipv4 INTERNAL domain portal.example.com
set firewall group domain-group ipv4 EXTERNAL domain updates.example.com

set firewall group domain-group ipv4 ALLOWED include-group INTERNAL
set firewall group domain-group ipv4 ALLOWED include-group EXTERNAL

set firewall ipv4 forward filter rule 120 action accept destination-domain-group ALLOWED
```

Inclusions stay within the same family and domain-group type. The normal eight-level
limit, cycle checks and reference protection apply. Refreshing a child also updates
its parents. Shared domains are resolved once per refresh using the highest required
round count. A parent's lookup settings apply to its own domains; included domains
keep their source group's settings.

Counters and last-used tracking can be configured per group or inherited from
`firewall global-options`. Refreshing unchanged addresses preserves element statistics.
A changed set's membership is replaced atomically, resetting its element statistics;
its referencing chains are not rebuilt.

## Lookup failures, cache and boot

The first configuration resolves uncached names through the system DNS servers.
Changing firewall configuration reuses cached answers. `commit check` does not query
DNS. The DNS configuration script runs after interfaces and before the main firewall.

A failed lookup emits a warning and keeps cached addresses. Without cached answers,
that name contributes no addresses. A failure ends that name's remaining rounds to
avoid repeated timeout delays; other names still resolve. Each lookup has a three-second
lifetime. Successful answers with no records for the selected family clear old addresses.

Answers are stored in `/config/domain-groups/cache.json`. Boot and rollback use this
cache without querying DNS; missing or unreadable cache data produces a warning and
empty membership. Neither domain groups nor GeoIP selectors are available beneath
`firewall fail-safe`, which loads before interfaces.

**There is no periodic refresh yet.** Answers remain installed until a manual refresh
or configuration change removes them. DNS TTL expiry alone does not remove them.
Cached addresses may become stale, so refresh when the domain's addresses change.
The future shared scheduler will handle automatic refresh.

## Operational commands

```text
update firewall domain-group
update firewall domain-group ipv4
update firewall domain-group ipv4 SERVICES

show firewall domain-group
show firewall domain-group ipv6 SERVICES

show firewall group domain-group ipv4 SERVICES
show firewall group domain-group ipv4 SERVICES detail
```

`update` performs fresh lookup rounds and refreshes changed membership in a single
nftables transaction. It requires the net-admin or administrator role. DNS runs
outside the configuration lock; before applying results, configd rechecks that no
commit, rollback or domain-group configuration change has intervened. A conflicting
update asks the caller to retry. No scheduler or timer is installed.

`show firewall domain-group` displays cached answers, last successful lookup, last
attempt and errors. `show firewall group domain-group` displays installed set members
and their counters using the normal firewall table format.
