# System DNS: implementation and maintenance

For configuration and command usage, see the [user guide](../users/dns.md).

## Ownership and lifecycle

The schema validates values and permitted paths. DNS has an independent `dns`
commit owner at `system name-server`, after interface application. The existing
hostname setting has its own `system` owner at `system host-name`, implemented by
`system_hostname.py` independently of DNS.
`system_dns.py` supplies resolver sources through netlinkd's root-only `replace-dns`
request; it never writes resolver files itself.

`helpers/dns.py` aggregates sources and atomically publishes a Jinja-rendered
`/run/nvyr-resolver/resolv.conf` with mode 0644. It writes only when contents change.
`nvyr-resolver-init.service` creates the readable runtime directory and points
`/etc/resolv.conf` at that file before netlinkd starts. Netlinkd is the only content
writer. The image masks systemd-resolved and resolvconf; networkd is already masked.
The init unit conflicts with those competing DNS services as well. Installation of
the package alone does not change the development host's resolver; the startup unit
takes ownership when the router services are started.

DHCP hooks continue to record lease events without modifying the resolver. Netlinkd
uses its event loop and a two-second maintenance pass over DHCP interfaces to publish
renewed DNS and remove expired/deconfigured leases or deleted interfaces. There is
no second daemon, lease watcher, commit or signal required. Lease generation tokens
and interface indices prevent stale records from contributing DNS. Pending interface
transactions temporarily suppress that owner's learned DNS until recovery.
Interface configuration changes publish immediately. Static interfaces are not
polled on this timer; the full safety audit runs every 60 seconds.

`/var/lib/nvyr-netlink/dns.json` journals same-boot DNS intent and incomplete updates.
Netlinkd restarts restore sources and recalculate current lease contributions; a new
boot discards previous unsaved intent until configd replays the saved configuration.
Failed updates compensate with the previous sources. Uncertain writes or lost RPC
replies use the existing configd recovery path. Background publication failures are
logged, exposed in netlinkd status and retried. No DNS state is added to the saved
configuration beyond the configured name-server values.

## Inspection and testing

```sh
readlink /etc/resolv.conf
cat /etc/resolv.conf

systemctl status nvyr-resolver-init nvyr-netlinkd
journalctl -u nvyr-netlinkd -b

sudo python3 -c 'from nvyr.helpers.interfaces import manager; print(manager.request("status"))'
```

`tests/test_dns.py` covers schema/lifecycle integration, aggregation, duplicate
removal, expiry, stale lease fencing, interface removal, service restarts, confirmed
rollback, failed publication and journal writes, RPC disconnects and automatic
publication by the actual netlinkd event loop. It uses isolated resolver files and
fake kernel operations. `tests/test_neighbor_dns_op.py` checks operational parsing,
provenance and DNS error reporting. `functionaltests/test_neighbor_dns.py` checks native
lookups against an isolated local DNS responder, including IPv4/IPv6 reverse
queries, CNAMEs and TCP fallback; it does not depend on public DNS.
`tests/test_netlink_live.py` additionally exercises real
udhcpc/dnsmasq DNS acquisition, expiry, removal and restart in a disposable privileged
container (`NVYR_NETLINK_TEST=1`), without touching the host resolver.

For image qualification, boot a disposable router VM with DHCP enabled on a test
port. Configure both a static name-server and that interface as a DNS source, commit
and save. Change the DHCP server's DNS option, renew the lease, and check the file
changes without a commit. Disable/delete the interface and check only static DNS
remains. Restart netlinkd and configd, then reboot and verify the saved configuration
is restored. Confirm `getent hosts example.com` works with a reachable test resolver
and that `/etc/resolv.conf` points to the managed file throughout.
