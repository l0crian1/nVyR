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

### 0.3.0 coverage audit

The release adds IS-IS, RIP/RIPng, CGNAT, imported firewall groups, static
neighbors and LLDP. All six are present in the combined saved configuration.
IS-IS and RIP/RIPng exchange distinct IPv4/IPv6 destinations between the default
instance and BOOTLEFT; their routes, forwarding and native FRR configuration are
checked before and after reboot. CGN's allocation map and lookup output are
checked in the default VRF; packet translation runs in the shared routed suite.
Imported IPv4/IPv6 lists and a positional CSV verdict map persist with provenance.

The complementary tests cover:

- IS-IS process/interface options, both levels and address families, policy
  withdrawal, conditional/always default origination and adjacency reset. Native
  dependency tests cover table-redistribution edits, removal and late route-map
  creation/deletion/recreation. Numbered OSPF instances, hidden OSPF timers and
  the previously deferred features are not part of this release's coverage claim.
- RIP/RIPng versions, authentication, filters, offsets, metrics, passive and
  split-horizon transitions. Shared traffic checks cover both families,
  redistribution, excluded routes and policy withdrawal; native tests retain
  the route-map lifetime and VRF refresh regressions.
- CGN allocation capacity/offset/conflict verification, pool updates and
  disable/re-enable/removal. Two subscribers request the same source port and
  must receive separate public port blocks with working TCP/UDP replies. ICMP
  identifiers, ordinary NAT exclusions and unmatched traffic have packet checks.
- List/CSV invalid-row isolation, ambiguous-key removal, duplicate provenance,
  unchanged hashes, bounded parallel retrieval, source failure and rollback.
  Native tests cover every supported import kind/map result, interval overlaps,
  dynamic expiry and the auto-merge comment limitation. Shared traffic tests
  verify direct refresh without replacing rules, conflict handling and retention
  of last published membership when a source becomes unavailable.
- Permanent ARP/NDP create/edit/delete and metadata readback, with shared
  forwarding checks for both families. Ownership, rollback and externally
  changed bindings remain lower-level regressions rather than additional
  release packet scenarios.
- LLDP selectors/exclusions, exact overrides, native readback and removal.
  Shared peers verify discovery on both VRF LANs and operational counters.

Firewall startup ordering has dedicated regressions: VRF zones and VRFs precede
the main firewall, interfaces follow it, and a firewall failure does not prevent
interface startup. The reboot scenario verifies the complete resulting ruleset.
Static management default routes are retained throughout acceptance; unrelated
routing policy and nondefault static routes still fail preflight.

This is a coverage inventory, not a claim that every hardware mode or external
service has been qualified. The release ISO must still run acceptance (including
reboot), smoketests and functional tests. Native dependency suites require their
documented disposable environment; skipped cases are not counted as passes.

Static ARP and IPv6 neighbors in `interfaces.set` cover permanent bindings and
descriptions on the shared default/VRF transit pair. `check_static_neighbors`
verifies both native tables and operational descriptions before and after reboot;
the existing routing checks exercise traffic over those bindings.

LLDP in `services.set` covers native wildcard selection, an excluded port,
custom system/chassis identity, management address, transmit timing and an exact
port override. `check_lldp` verifies installed native state and operational output
before and after reboot. It needs no external LLDP neighbor.

DNS forwarding in `services.set` covers default and BOOTLEFT instances,
dual-stack listeners, conditional/TLS upstreams, cache and worker settings,
DNSSEC controls, local publication and logging. Native configuration and local
A/AAAA answers are checked after reboot without requiring Internet connectivity.
Incompatible transport combinations, disable/removal and real upstream exchanges
are covered by the smoke and native functional suites.

OSPFv2 and OSPFv3 in `ospf.set` share BGP's default-instance/BOOTLEFT transit.
Both use timed authentication keychains and advertise destinations independent
of BGP: `dum996` from BOOTLEFT and `lo` from the default instance. Their checks
verify both adjacencies, main-table and VRF routes, traffic in both directions,
and operational output; the native FRR snapshot also covers restored options.
Global opaque capability and router-info coexist with the named-VRF process.
Graceful restart uses 15 seconds: both peers reboot together and cannot supply
each other's pre-restart LSDB, so recovery can require the full grace-period
expiry. The short period keeps that expected behavior within the route deadline.
Alternative area types and authentication modes have dedicated smoketests.

DHCPv4 socket selection covers explicit `udp` on the default instance and the
implicit `raw` default in BOOTLEFT. Both native settings are checked before and
after reboot; real relayed packet exchange is covered by the isolated Kea suite.

DHCP HA in `services.set` covers active-active IPv4 alongside hostfile updates,
active-passive IPv6 with independent listener ports, and VRF-scoped IPv6 secondary
and backup roles. `check_dhcp_ha` and the native configuration snapshots verify
restored hooks, roles, URLs and role-based pool portions. Those remote peers are
deliberately absent; actual allocation, replication and failover are covered by
the isolated HA functional suite rather than the reboot fixture.

The default DHCPv6 instance includes a /48 delegation pool and a reservation
with both an address and a fixed /56. `check_dhcp6_server` checks the applied
aggregate, delegated length, and reservation after configuration and reboot.

BGP unicast additions in `routing.set` exercise negotiated capabilities and roles,
prefix limits, AS-path filters and next-hop selection on the existing active
IPv4/IPv6 pair between the default instance and BOOTLEFT. Both sides must learn
the expected policy attributes, install BGP routes and exchange traffic. Export
prefix filters keep OSPF-only destinations out of BGP; aggregate suppression uses
a separate static prefix so it cannot suppress the live test destinations.
Separate shut-down peers retain alternate local AS, transport
overrides, graceful shutdown, capability alternatives, route-server settings,
AS-path transformations, conditional advertisements and AddPath alternatives.
Interface/link-local peers, aggregate attributes, redistribution metrics and
administrative distances are also saved. `check_bgp_unicast_options` checks
negotiated state and representative native commands; complete FRR snapshots
are compared across reboot. BOOTRIGHT remains for VLAN, DHCP, container and
cross-VRF static-route coverage; the base routing transit is in the default instance.

| Feature | Fixture | Native evidence before and after reboot |
| --- | --- | --- |
| Time zone | `services.set`: `America/New_York` | `check_system_timezone` checks `/etc/localtime`, `/etc/timezone`, and `show date` before and after reboot. UTC restoration and invalid selections have dedicated smoketests. |
| Scheduled tasks | `services.set`: month-end weekday audit and disabled shell interval | `check_system_tasks` checks the armed timer and disabled task before and after reboot. |
| CPU policy | Existing system settings, or unconfigured boot behavior | `check_cpu_policy` reads CPUFreq governors and explicit energy preferences before and after reboot. No CPUFreq means a recorded skip. Alternative governors, EPP removal and invalid combinations have dedicated smoketests. |
| Global kernel settings | `firewall.set` | Every managed scalar/default/all gate is read from procfs; automatic capacities must be positive. Nondefault ARP and timeout values are explicit. |
| Interface IPv4/IPv6 policy | `interfaces.set` | Every registered setting is explicitly represented; procfs overrides, token, EUI-64 address, explicit/suppressed link-local and persistent privacy-secret creation are checked. |
| VRF routing and conntrack | `interfaces.set`, `services.set` | Routing barriers, distinct zones, VLAN/container memberships, cross-VRF traffic and the complete zone table are checked. |
| Inet firewall and providers | `firewall.set` | Shared rules at all hooks, a named chain, map, match-group, limit-group and ICMPX rejection are installed before family dispatch. |
| Ingress and VLAN matching | `firewall.set` | IPv4/IPv6/inet dispatch, recreated interfaces, future-device prefixes, VLAN concatenations and notrack are checked. |
| NAT and NAT66 | `firewall.set` | Both families retain their own same-numbered DNAT rule, address/port map and source masquerade across reboot. |
| Map default results | `firewall.set` | IPv4/IPv6/inet verdict defaults and address/port NAT defaults remain native catch-all entries. |
| Source validation | `firewall.set` | IPv4/IPv6 strict and loose overrides are scoped to lab links. |
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
- DHCPv6 acceptance uses a healthy local ISP instance and downstream RA client.
  It checks two delegations, subnet/host IDs, SLAAC acquisition, a learned default
  route, DHCPv6 DNS/search domains and stable DUIDs across reboot. PD-only WANs,
  renew/release, renumbering and expiry are covered by the shared-interface
  functional scenario rather than repeated during boot qualification.
- NTP sources deliberately cannot synchronize the clock; startup, ACLs and
  configuration recovery do not depend on public DNS or a remote time server.
- Trace capture/story output and setter/timeout/helper packet semantics have
  separate native tests. This scenario checks their installed definitions.
- Choice alternatives and rejected combinations remain in feature smoketests.


## Qualification status — 2026-11-05

Run `9b47e21c-50c6-4ce6-9f22-7ad74f1fe066` passed all 87 preboot checks and
all 93 postboot checks on the installed 0.2.0 test router, using physical `eth5`
with carrier. The native nftables/FRR snapshots, running/saved configuration,
VRF conntrack ownership and DHCPv6 DUIDs matched. The runner restored the
original running and saved configuration. Test artifacts are retained locally
under `experiments/qualification-020/` (excluded from Git).

The accompanying functional run passed all 417 retained cases; the disruptive
CLI-login case remained opt-in and was skipped. The run also executed one Lua
packaging probe that has since been removed because no nVyR feature consumes it.
The smoke run passed 1,270 cases and exposed one stale assertion for Kea's omitted
default socket type. After correcting that assertion, all 16 DHCP smoke cases
passed. Bond coverage includes all seven modes and native option readback in
smoketests, plus dual-stack failover and LACP forwarding in functional tests.

The router used Linux 6.18.59-nvyr-amd64, FRR 10.7.1 with nVyR's second package
revision, and the updated test files from this checkout. Its image metadata still
identifies the November 4 build (`2026-11-04T14:25:49Z`). This qualifies that
installed runtime with these tests; all installed nVyR Python sources matched
the checkout. It does not certify the newer ISO being built
without installing and testing that image.

The first attempt passed the feature checks but failed the full FRR comparison:
three empty VRF stanzas from earlier tests disappeared at reboot. The static
route adapter deliberately retains VRF declarations when removing routes, even
after the corresponding Linux VRFs disappear. The failure and its snapshots
remain recorded under run `553a9d6f-3cdc-41c3-9474-84f9d5e56774`. No comparison
exception was added; the repeat run started after reboot and restoration.

[NFT-IFNAME-001](../docs/dev/upstream-issues.md#nft-ifname-001-adjacent-interface-prefixes-corrupt-anonymous-set-listings)
remains tracked as an upstream defect, not a release blocker. The fixture uses
nonadjacent `veth995*` and `veth997*` prefixes and retains the complete native
snapshot comparison; the adjacent-prefix reproducer remains in the issue record.
