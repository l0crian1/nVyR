# Router initialization

The Debian package supplies baseline host networking through existing systemd
services. It is independent of the candidate configuration and configuration-script
lifecycle; there is no feature-dispatching startup script.

## Boot ordering and nftables

`nftables.service` loads `/usr/lib/nvyr/router.nft` through a packaged drop-in:

```nft
flush ruleset
add table inet nvyr_filter
```

This is one atomic nftables transaction. It deliberately replaces **all** inherited
rules, including unrelated tables, at startup. It creates no chains or default policy.
An unconfigured router therefore forwards without nVyR filtering; firewall policy
must be configured explicitly. Optional [fail-safe protection](firewall-failsafe.md)
loads into its own table before interface configuration. The main firewall runs
after interfaces and removes that temporary table in the same transaction that
installs the full policy.

The image enables nftables early in boot, before `network-pre.target`. Configd both
requires and starts after nftables and `systemd-sysctl.service`. Failure to start a
required baseline service prevents configd from starting. A missing baseline nft file
fails an assertion instead of silently skipping initialization. Debian's example
`/etc/nftables.conf` is no longer used by this service.

Normal commits and configd restarts do not reset nftables. An explicit
`systemctl restart nftables` resets the baseline and restarts configd through its
`PartOf` relationship, reconciling durable running configuration. A machine reboot
selects saved configuration instead, so use `save` for changes that must survive
reboot. This restart has a period with no configured filtering; use ordinary commits for live policy updates. Reload is
disabled because loading only the baseline would erase policy without replaying it.
Stopping nftables leaves current kernel rules intact, including during shutdown.

## Daemon recovery

Interface naming, netlinkd and configd use systemd's `Restart=on-failure` with
`RestartMode=direct`. A failed process returns to activation without invalidating
dependent startup jobs. If naming fails before reporting readiness, netlinkd and
configd stay queued until naming succeeds. If netlinkd fails before readiness,
configd stays queued until its control service is ready.

Naming and configd initially retry after five seconds; netlinkd retries after two.
Three increasing delay steps reach a maximum of 30 seconds between attempts.
Automatic attempts have no count cutoff, so a temporary problem does not require
an administrator to run `reset-failed`. This delay is in addition to the time each
startup attempt takes. Errors remain in the service journal; a retrying daemon
shows `activating (auto-restart)`, not a healthy running state.

A crash after readiness restarts only that daemon. Healthy peers remain running,
and existing kernel interfaces, routes and firewall rules are not cleared by the
service restart itself. Each daemon uses its existing durable recovery process;
configd reconciles the running configuration on a same-boot restart. A reboot
instead restores the saved configuration.

An explicit `systemctl stop` cancels retries and remains effective. Stopping naming
explicitly also stops its required consumers; restarting the desired services is
then an administrative action. These policies do not retry failed commits, repair
invalid configurations, detect a hung process, or automatically recover a failed
external prerequisite such as nftables initialization. Required readiness checks
remain in force.

Inspect a recovering service with:

```sh
systemctl status nvyr-interface-naming nvyr-netlinkd nvyr-configd

systemctl show nvyr-configd -p ActiveState -p SubState -p NRestarts -p RestartUSecNext
journalctl -b -u nvyr-configd
```

The policies use features provided by the image's systemd 257; see the
[systemd service documentation](https://www.freedesktop.org/software/systemd/man/257/systemd.service.html#RestartMode=).
`tests/test_daemon_recovery_live.py` tests real systemd startup dependencies,
crashes, retry backoff and intentional stops with disposable unit names. It
requires an explicit `NVYR_RECOVERY_TEST=1` and root access; it does not alter the
installed router services or their network configuration.

## Kernel settings

`/usr/lib/sysctl.d/50-nvyr-router.conf` defines persistent router defaults. It is
generated from `src/nvyr/helpers/kernel_settings_map.py`, the same keymap used by
the firewall kernel-settings helper:

- IPv4 and IPv6 forwarding enabled globally and on interfaces.
- IPv4/IPv6 redirect acceptance disabled, and IPv4 redirect sending disabled.
- IPv4 source routing disabled; IPv6 retains the kernel's restricted type-2
  routing-header behavior instead of indiscriminately blocking routing headers.
- IPv4 reverse-path filtering disabled so asymmetric and policy routing work;
  source-validation policy belongs in feature configuration.
- IPv4 directed-broadcast forwarding disabled.
- Kernel IPv6 RA acceptance follows router mode (`accept_ra=1`), leaving room
  for a future per-interface RA client to opt in. Managed interfaces currently
  default to per-link accept_ra=0 and autoconf=0 through netlinkd. Explicit
  interface IPv6 options can enable RA/SLAAC; see [interface options](../users/interfaces.md#ipv4-and-ipv6-options).
- IPv4 PMTU discovery retained, without trusting learned PMTU for transit traffic.
- Unicast echo replies enabled, broadcast/multicast echo replies disabled, and
  TCP SYN cookies enabled for local listening sockets.

The boot file contains only this early router baseline. Detailed ARP controls,
ICMP rate limits, diagnostics, conntrack settings and flowtable timeouts belong to
the firewall helper. Startup runs that helper even without a configured firewall,
applying their defaults without adding a packet-filtering policy.

IPv4 forwarding is written first because changing it resets IPv4 host/router
defaults. Each interface default precedes a glob that covers existing interfaces,
including names containing dots. New links inherit defaults; systemd's normal udev
integration also applies interface sysctls as links appear. Netlinkd does not overwrite these global forwarding defaults.

Firewall global options publish `/run/sysctl.d/90-nvyr-firewall.conf` so subsequent
udev initialization uses the configured values, rather than resetting new links
to the packaged baseline. Deleting an option restores its nVyR default. Interface
`all` controls use setting-specific neutral values: for example, source routing
has an open global gate but remains disabled on each interface by default. This
permits future explicit interface overrides without changing unrelated links.

`nvyr-conntrack.service` loads conntrack and its diagnostic logger before configd.
It records automatic connection-table capacities in
`/run/nvyr-kernel-settings/auto.json` once per boot. Selecting `auto` later restores
those original capacities, including after a configd restart.

IPv6, DAD, neighbor discovery, multicast support, ECN, protocol support, queue sizes
and buffer sizing are not disabled or tuned here. There are no topology assumptions
about NAT, routing protocols or VRFs. Configured ARP and ICMP behavior is controlled
through [firewall global kernel settings](../users/firewall.md#global-kernel-settings).

The choices and interface semantics follow the
[Linux IP sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html),
[systemd sysctl.d rules](https://github.com/systemd/systemd/blob/v257/man/sysctl.d.xml).
Unmanaged kernel settings still follow normal systemd precedence. nVyR owns the
registered firewall settings and reconciles them on firewall apply; do not manage
those same keys independently in another sysctl file. This is configuration
application, not a watchdog continually undoing runtime changes.

## Installation and verification

The nVyR install script does not start services or flush rules. Debian's systemd
package trigger may immediately apply newly installed sysctl files and restart
configd if it is already active; configd also has a `PartOf` relationship with
systemd-sysctl so restarting that prerequisite restores normal operation. Save
committed configuration before upgrades. The image enables services for the next boot. On an existing
installation, reboot to apply the complete baseline; merely restarting configd does
not rerun an already-active nftables or sysctl service. Installing this package on a
general Debian host changes its next boot into router behavior and replaces its
previous nftables ruleset.

The opt-in `tests/test_initialization_live.py` checks the installed files in a
disposable privileged systemd container. It tests an empty, repeatable nft baseline,
existing/new interface sysctls, real IPv4/IPv6 forwarding in separate network
namespaces, configd restart preservation, nftables restart policy replay and
prevention of configd startup when nftables initialization fails.
Run with `NVYR_NETWORK_TEST=1` only in that disposable environment.
