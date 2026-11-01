# DHCP servers: implementation and maintenance

For configuration and command usage, see the [user guide](../users/dhcp-server.md).

## Lifecycle and packaging

Interface configuration changes trigger the declarative DHCP script watch. Native
reconfiguration preserves leases; socket-binding changes stop the old binding
before starting replacements. Failure compensates previously changed instances.
Disabling or deleting a server stops its unit and removes runtime configuration;
lease files remain under the configd state directory's `kea/` subtree.

The DHCPv4 schema supplies a direct `socket-type` default of `raw`. Generation
copies it to `interfaces-config.dhcp-socket-type`; listener selectors never infer
the mode. DHCPv6 omits the IPv4-only native setting. The manager compares the full
`interfaces-config`, so changing socket type stops the old listener before
installing its replacement, with the existing compensation on failure.

Administratively enabled ports without carrier are accepted at commit and boot.
The commit reports that DHCP is waiting for carrier. Kea retries opening its
service sockets once per second; after 12 retries, systemd restarts the instance
and continues retrying. Serving starts automatically when the link becomes ready.
DHCPv6 also waits for link-local address readiness. Administratively disabled
listeners and unrelated socket failures remain errors.

Runtime configuration and control sockets are under `/run/nvyr-kea/`. Units are
`nvyr-kea@<family>-<hex-encoded-vrf>.service`. The ISO includes pinned ISC Kea 3.0.4
packages and masks the stock Kea services. nVyR refuses to compete with an active
stock server. A `.deb` upgrade requires installing the new dependencies as well;
`dpkg -i` alone does not fetch them.

Live configuration checks ship in `/usr/lib/nvyr/smoketests/test_dhcp_server.py`
and `/usr/lib/nvyr/smoketests/test_dhcp_hosts.py`.
Packet allocation/renewal and overlapping-VRF checks are opt-in development tests
in `tests/test_kea_live.py`, requiring an isolated privileged container with Kea,
Scapy, iproute2, and `NVYR_KEA_TEST=1`. They must not run on a production LAN.
The UDP relay regression sends DISCOVER and REQUEST from a separate namespace to
a dummy /32 through a veth, and requires OFFER and ACK replies. Existing direct
broadcast tests retain raw sockets.
The hostfile packet test also needs the run-script hook and an installed/importable
`nvyr` package. Its disposable container must have no systemd installation: the
test substitutes the systemctl dispatch while exercising the packaged hook and
real Kea lease events against temporary hosts files.

## High availability

The shared `service/dhcp-ha.yaml.i` schema supplies the global and per-VRF HA
subtrees. DHCPv6 replaces the two port defaults with 8006; DHCPv4 uses 8005.
Defaults are direct, so an absent HA node never enables the feature.

`service_dhcp.get_config()` gathers both families' configured HA listeners for
collision checks and the existing interface inventory. `verify()` checks local
identity, peer completeness, role combinations, duplicate endpoints and source
address ownership. It emits the shared `Warning` object about matching ranges;
it does not contact a peer or block boot waiting for synchronization.

`generate()` loads `libdhcp_lease_cmds.so` before `libdhcp_ha.so`, retaining the
Unix control socket and any DHCP hostfile hook. The HA hook provides its own HTTP
listener. Core DHCP processing and the HA HTTP client/listener each use two
threads rather than allocating a thread per available CPU. `active-active` maps
to `load-balancing`; `active-passive` maps to `hot-standby`. Existing per-VRF
`ip vrf exec`, native config-set, compensation and service supervision apply.

Active-active pools require disjoint address ownership, as documented in
[Kea's load-balancing configuration](https://kea.readthedocs.io/en/kea-3.0.4/arm/hooks.html#load-balancing-configuration).
Native 3.0.4 tests with identical unclassified ranges produced DHCPACKs granting
the same address to different clients on healthy peers. This is a documented
configuration requirement, not an upstream defect.

`allocation_pools()` splits each range at its midpoint, using integer arithmetic
even for IPv6 /64-sized ranges. The primary gets the lower half (including any
odd extra address), the secondary the upper half. Native `client-classes` select
`HA_<primary-name>` and `HA_<secondary-name>`. The entire mapping is emitted on
all members, including backups. Kea widens its served scopes during takeover.
Appending a range leaves existing ownership boundaries untouched. Singleton
ranges produce one primary-owned pool; reservation-only subnets need no split.
Active-passive and non-HA instances retain their original pools.

`tests/test_kea_ha.py` checks CLI defaults/anchoring, completeness, endpoint and
VRF validation, warning delivery, deterministic splits and hook removal. Installed
smoketests inspect native config-get output without waiting for a partner.
`functionaltests/test_dhcp_ha.py` creates one isolated fabric with four peers,
covering both families, concurrent exhaustion, lease replication, controlled
takeover, partner failure and resynchronization. The active-passive peers run
inside VRFs. It uses real Kea hooks and ordinary failure timers; it does not touch
management interfaces or the host firewall. Run it as root:

```bash
python3 -m pytest -v -s /usr/lib/nvyr/functionaltests/test_dhcp_ha.py
```

The acceptance fixture saves HA settings, peer/port defaults, split pools and
hostfile-hook coexistence. Its deliberately absent remote peers are not an HA
availability test; lease exchange and failover belong to the functional suite.

## Lease hostname updates

Kea lease events request a short-lived systemd updater. It rebuilds a marked DHCP
section from the current lease journal, including Kea's lease-file cleanup
rotation. Renewals update names; released, declined, expired and removed-subnet
leases are omitted. Configuration application reconciles immediately. A one-minute
timer also reconciles after boot and catches expired leases or coalesced events.
There is no dedicated hosts-file daemon.

## Hostfile packaging

The package and ISO include `isc-kea-hooks`, which supplies Kea's run-script hook.
When installing only a `.deb`, install its dependencies too. The updater units
are `nvyr-dhcp-hosts.service` and `nvyr-dhcp-hosts.timer`.
