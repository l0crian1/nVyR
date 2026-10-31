# GeoIP address-groups

Address-groups can select countries from [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite).
Country Lite is published monthly; nVyR checks for a changed release daily at midnight in the router's timezone.

## Configuration

```text
set firewall group address-group ipv4 NORTH_AMERICA geoip country US country CA
set firewall group address-group ipv6 NORTH_AMERICA geoip country US country CA

set firewall ipv4 input filter rule 10 action drop source-address-group NORTH_AMERICA
set firewall ipv6 input filter rule 10 action drop source-address-group NORTH_AMERICA

commit
```

Country codes are uppercase and have completion suggestions. Multiple countries are combined in one group.
A GeoIP group cannot also contain configured addresses or use packet-learned `dynamic` membership.
Normal group references, negation, descriptions, counters, and last-used tracking remain available.

## Download failures and boot behavior

The first apply attempts to download and validate the database. If that download fails
and no cache exists, the commit succeeds with empty GeoIP groups and prints a warning.
The scheduled or manual updater populates them after a successful download. Empty groups
have no country matches, so a rule blocking selected countries will not block those
addresses until data is available. `commit check` never downloads the database.

Subsequent configuration changes use the persistent cache in `/config/geoip/` without
contacting DB-IP. Boot recovery also uses the cache and never attempts a download;
if no cache exists, it loads empty GeoIP groups and logs a warning. GeoIP is excluded
from the fail-safe firewall. An existing corrupt or unreadable cache still reports
an error. Keep the cache directory with your router backups. The initial download
needs DNS and HTTPS access to DB-IP. System name servers are applied before the main firewall.

## Updates and status

```text
update firewall geoip

show firewall geoip
```

Updating requires net-admin access; operators can view status. The manual command and
`nvyr-geoip-update.timer` use the same updater. With no configured GeoIP groups, neither downloads anything.
The timer catches up after a missed midnight run. A busy commit or rollback prevents the update;
retry the manual command afterward, or wait for the next scheduled run.

The updater reads DB-IP's published SHA-1 for the **uncompressed CSV**, downloads a changed
generation, and validates its checksum, records, and address ranges before loading it. An unchanged
checksum leaves the sets untouched. A failed download or rejected nftables transaction retains the
previously applied database and membership. Status distinguishes downloaded and applied releases.
Downloads are bounded to 32 MiB compressed, 128 MiB expanded, and two million records.

All configured GeoIP groups refresh in one nftables transaction: flush their elements, then load
their new contents. Referencing chains, rule counters, and set identities remain intact; replaced
elements start fresh element counters and last-used values. Immutable downloaded generations are
retained in the cache. GeoIP addresses are runtime data, not individual entries in saved configuration.

All non-dynamic address-groups use nftables interval auto-merge, including ordinary configured
addresses. Packet-learned dynamic groups keep individual entries and independent expiration times.

## Attribution

IP Geolocation by [DB-IP](https://db-ip.com). Country Lite data is licensed under
[Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/).
nVyR selects country ranges and merges adjacent/overlapping ranges when loading them into nftables.
Geolocation describes DB-IP's country classification, not a guarantee of a user's physical location.
