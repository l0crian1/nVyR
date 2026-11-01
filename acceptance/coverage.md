# Release acceptance coverage

The combined fixtures exercise configuration application, persistence and native
recovery. They are not a replacement for rejection tests, packet matrices or tests
of mutually exclusive modes in `smoketests/`.

The physical Ethernet IPv6 address check (including its VLAN child) is skipped
when the selected spare port has no carrier. The reason is retained in preboot
and postboot results. Carrier is checked independently in each phase; with a
link present, missing IPv6 addresses remain failures. Interface configuration,
IPv4 addresses and virtual-network traffic checks still run without a cable.

## Recent configuration additions

DHCPv4 socket selection covers explicit `udp` on the default instance and the
implicit `raw` default in BOOTLEFT. Both native settings are checked before and
after reboot; real relayed packet exchange is covered by the isolated Kea suite.

DHCP HA in `services.set` covers active-active IPv4 alongside hostfile updates,
active-passive IPv6 with independent listener ports, and VRF-scoped IPv6 secondary
and backup roles. `check_dhcp_ha` and the native configuration snapshots verify
restored hooks, roles, URLs and role-based pool portions. Those remote peers are
deliberately absent; actual allocation, replication and failover are covered by
the isolated HA functional suite rather than the reboot fixture.

BGP unicast additions in `routing.set` exercise negotiated capabilities and roles,
prefix limits, AS-path filters and next-hop selection on the existing active
IPv4/IPv6 pair. Separate shut-down peers retain alternate local AS, transport
overrides, graceful shutdown, capability alternatives, route-server settings,
AS-path transformations, conditional advertisements and AddPath alternatives.
Interface/link-local peers, aggregate attributes, redistribution metrics and
administrative distances are also saved. `check_bgp_unicast_options` checks
negotiated state and representative native commands; complete FRR snapshots
are compared across reboot. The revised fixture passes local validation; a new
full appliance reboot run is still required for qualification.

| Feature | Fixture | Native evidence before and after reboot |
| --- | --- | --- |
| Time zone | `services.set`: `America/New_York` | `check_system_timezone` checks `/etc/localtime`, `/etc/timezone`, and `show date` before and after reboot. UTC restoration and invalid selections have dedicated smoketests. |
| CPU policy | Existing system settings, or unconfigured boot behavior | `check_cpu_policy` reads CPUFreq governors and explicit energy preferences before and after reboot. No CPUFreq means a recorded skip. Alternative governors, EPP removal and invalid combinations have dedicated smoketests. |
| Global kernel settings | `firewall.set` | Every managed scalar/default/all gate is read from procfs; automatic capacities must be positive. Nondefault ARP and timeout values are explicit. |
| Interface IPv4/IPv6 policy | `interfaces.set` | Every registered setting is explicitly represented; procfs overrides, token, EUI-64 address, explicit/suppressed link-local and persistent privacy-secret creation are checked. |
| VRF routing and conntrack | `interfaces.set`, `services.set` | Routing barriers, distinct zones, VLAN/container memberships, cross-VRF traffic and the complete zone table are checked. |
| Inet firewall and providers | `firewall.set` | Shared rules at all hooks, a named chain, map, match-group, limit-group and ICMPX rejection are installed before family dispatch. |
| Ingress and VLAN matching | `firewall.set` | IPv4/IPv6/inet dispatch, recreated interfaces, future-device prefixes, VLAN concatenations and notrack are checked. |
| Map default results | `firewall.set` | IPv4/IPv6/inet verdict defaults and address/port NAT defaults remain native catch-all entries. |
| Source validation | `firewall.set` | IPv4/IPv6 strict and loose overrides are scoped to lab links; the fail-safe uses the inet syntax. |
| Packet tracing and modification | `firewall.set` | nftrace, packet/connection marks, DSCP, TTL/hop limit, fixed MSS and route-based MSS statements are checked. |
| Timeout groups | `firewall.set` | IPv4/IPv6 TCP and inet UDP objects and assignments are checked. All TCP and UDP state options are explicitly configured. |
| Conntrack helpers | `firewall.set` | FTP, TFTP and both SIP transports are selected through the shared map in INPUT/FORWARD/OUTPUT, in the expected order. |
| Flowtable accounting | `firewall.set` | Native counter flag, the global enrollment counter and prefix hook attachments are checked. |
| Pod networking | `services.set` | Two running members share pod identity, hostname and dual-stack addresses; Netavark interface naming and master are checked. |
| NTP | `services.set` | Chrony responds in BOOTLEFT with server/pool/NTS/prefer directives, both listener families and working allow/deny ACLs. |

## Existing combined coverage

The original fixture continues to cover Ethernet, dummy, loopback, veth, VIFs,
bridges, VRFs, DHCP clients and servers, static routes, BGP peers and route policies,
containers, persistent volumes, file/NFLOG logging, firewall singleton/concatenated
groups, includes, dynamic learning, quotas, limits, connection matching, zones,
raw hooks, flowtables and NAT. See [the suite README](README.md) for the complete
scenario and required lab resources.

## Boundaries

- GeoIP downloads and domain-group DNS refresh remain external-data tests, not
  claims of this reboot scenario. Their cache/failure behavior has separate tests.
- SLAAC address acquisition requires an RA sender. This fixture checks restored
  RA/SLAAC settings and tokens, not receipt of an advertised prefix.
- NTP sources deliberately cannot synchronize the clock; startup, ACLs and
  configuration recovery do not depend on public DNS or a remote time server.
- Trace capture/story output and setter/timeout/helper packet semantics have
  separate native tests. This scenario checks their installed definitions.
- Choice alternatives and rejected combinations remain in feature smoketests.
- A fail-safe table being absent after startup proves handover, not the duration
  or packet behavior of the early boot protection window.

## Qualification status — 2026-10-27

The expanded configuration passed local real validation/generation, saved-state
replay and restoration tests. A live preboot run on the October 27 ISO reached
the native observations: 74 of 76 checks passed. The two failures both expose
[NFT-IFNAME-001](../docs/dev/upstream-issues.md#nft-ifname-001-adjacent-interface-prefixes-corrupt-anonymous-set-listings).
Full-table JSON loses adjacent wildcard entries and emits a warning, preventing
complete native snapshot comparison. The base configuration now uses the
nonadjacent `veth995*` and `veth997*` prefixes, with matching interface names and
references throughout the fixture. Wildcard coverage and full snapshot checks
remain in place; the adjacent-prefix reproducer remains in the upstream issue.

This is tracked as an upstream defect, not a release blocker. No reboot
qualification is claimed for the revised configuration until the full
save/reboot/restore run passes. This fixture update has not been run. Failed runs retain their
original configuration backups and installed test state for inspection.
