# DNS forwarding implementation

`service_dns_forwarding` owns the default and named-VRF forwarding instances.
Its lifecycle gathers effective service sections and static host mappings,
verifies relationships and address ownership, generates native configuration,
and installs the resulting immutable plan. Scalar validation remains in the
schema. Configd does not configure Unbound itself.

`templates/dns/unbound.conf.j2` renders native Unbound configuration directly.
`helpers/dns_forwarding.py` supplies runtime snapshots, file/service operations,
and a one-shot refresh entry point. There is no DNS proxy or query worker in
nVyR: Unbound processes every client query.

## Runtime and recovery

Each instance is named with the hexadecimal UTF-8 VRF name. Its root-owned
configuration and observation files are under `/run/nvyr-dns/<id>`. A separate
Unbound-owned socket directory contains its UNIX control socket; the daemon
cannot replace its root-owned configuration. `/config/dns/<id>/root.key` holds
the RFC 5011 trust anchor and survives image upgrades.

The launcher uses `ip vrf exec` for named VRFs before Unbound drops privileges
to its package user. Default-instance sockets use the default routing domain.
The distribution's stock Unbound unit is masked; nVyR starts only its configured
units. All desired instance configurations pass `unbound-checkconf` before any
existing instance is changed. Configd's existing recovery lifecycle reapplies
the previous effective configuration after an apply failure.

The unit disables systemd's start-rate limit so rapid valid commits and rollback
cannot exhaust it. Failed processes still restart with a two-second delay;
apply checks control-socket readiness and reports startup failures.

Apply and refresh take the same file lock. Successful apply publishes the
desired configuration snapshot for refresh; refresh never changes running or
candidate configuration. Restart, removal, disable and failed activation retain
ordinary error reporting. There are no persistent runtime inventory migrations:
`/run` is recreated at boot and saved configuration is authoritative.

The refresh timer runs five seconds after its preceding invocation ends. It
reads DHCP/RA sources through netlinkd's read-only `dns-sources` operation,
current interface inventory, and Kea's existing lease reader. It does not read
`resolv.conf`. Unchanged files are neither rewritten nor reloaded. Address or
static configuration changes restart the instance; changing only upstreams or
local records uses `reload_keep_cache`.

Unbound accepts an empty forward-zone and responds SERVFAIL without recursion.
Use that behavior while learned upstreams are unavailable. Do not substitute a
public resolver or silently remove the forwarding zone. Explicit conditional
zones use transparent local zones so Unbound's built-in private reverse zones
do not intercept an intentionally configured forwarding policy.

## Dependency support

Use Debian trixie's maintained Unbound package and security updates, plus
`dns-root-data`. Debian's security team tracks and fixes this release; repository
availability is not the support rationale. The first native validation used
`1.26.2-0+deb13u1` from trixie-security. Review the
[Debian security tracker](https://security-tracker.debian.org/tracker/source-package/unbound)
and [Unbound upstream releases](https://nlnetlabs.nl/projects/unbound/download/)
when changing the dependency. Native configuration is documented in the
[Unbound manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html).

## Verification

- `tests/test_dns_forwarding.py`: schema, lifecycle, relationship validation,
  independent learned sources, loop prevention and local record formatting.
- `NVYR_DNS_NATIVE=1 pytest tests/test_dns_forwarding_native.py`: isolated native
  IPv4/IPv6 UDP/TCP forwarding, cache, conditional forwarding, empty upstreams,
  all exposed native directives, TLS identity validation and record reloads.
- `smoketests/test_dns_forwarding.py`: configuration translation and rejected
  combinations against the installed service; no packet or convergence waits.
- `functionaltests/network/test_dns_forwarding.py`: real DNS clients using
  default and VRF listeners in the existing routed-network scenario.
- Reboot acceptance publishes the existing dual-stack static host mapping and
  checks default/VRF service state and local answers before and after reboot.
