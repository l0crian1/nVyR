# Operational-command test lab

This lab uses **eth1 and eth2**, two VRFs (`OPSA`/`OPSB`), and virtual links to
populate the operational views added during the coverage audit. It assumes an
otherwise basic development configuration, unused eth1/eth2, and unused `OPS*`
names, `veth60`–`veth65`, `br60`/`br61`, and `dum60`.

The configuration does not reconfigure eth0, login accounts, or the management
default route. Its regular firewall defaults are accept. Existing overlapping
firewall, DHCP, container or interface configuration can change the results;
this is a complete example, not a replacement/cleanup script for arbitrary
existing configurations.

## Files

- [config.set](config.set): complete configuration commands, grouped by feature.
- [show-commands.txt](show-commands.txt): full operational commands for inspecting
  services, interfaces, routing, containers, DHCP, NTP, firewall and system state.
- [traffic.txt](traffic.txt): traffic-generation commands and immediate runtime checks.
- [actions.txt](actions.txt): renew/release, managed restart, clear/reset, streaming
  statistics and diagnostic generation. Run these individually after inspection.

## Apply

From operational mode, preload the container image:

```text
add container image alpine

configure
```

Paste the `set` lines from `config.set`, then:

```text
commit
exit
```

Alternatively, copy `config.set` to `/config/operational-lab.set` on the router
and run this in configuration mode:

```text
load set /config/operational-lab.set

commit
exit
```

This merges the configuration. Do not use `replace` if retaining the management
configuration. The operational command files contain explanatory `#` lines;
run their commands without pasting those comments.

Allow about a minute for the DHCP client, BGP peers and spanning tree. Start with:

```text
show system services
show interfaces

show dhcp-client interface br61 detail

show bgp vrf OPSA summary
show bgp vrf OPSB summary

show containers
```

All commands in the operational files are written for the operational prompt.
Prefix a command with `run` if remaining in configuration mode. `save` is optional;
use it only if retaining this lab across reboot.

## What the configuration supplies

- **Physical interfaces:** eth1 is `10.60.10.1/24` / `2001:db8:60:10::1/64` in
  OPSA; eth2 is `10.60.20.1/24` / `2001:db8:60:20::1/64` in OPSB. eth1.100 adds
  VIF detail. Both physical ports have a link-group.
- **VRF peering:** veth60/veth61 connect OPSA and OPSB. FRR exchanges the two LAN
  prefixes over both IPv4 and IPv6 BGP sessions. Applied route maps add communities
  and attributes, so policy and route inspection have real consumers.
- **DHCPv4:** the default-VRF server on veth64 leases to br61 in OPSB through its
  veth65 member. This produces a real lease without an external client. A second
  server on eth1 supplies pool `OPSLAN` in OPSA.
- **DHCPv6:** both server scopes have configured pools and listeners. A DHCPv6
  client connected to eth1 is needed to produce IPv6 lease records. No router
  advertisement configuration is included; request DHCPv6 explicitly on that client.
- **Bridge:** br60 has spanning tree, a static MAC entry, IPv4/IPv6 addresses and
  the veth62 member. Its veth63 peer in OPSB is the NTP test client.
- **Containers:** `OPSWEB` serves HTTP on port 8080 using Alpine's BusyBox httpd.
  Its network `OPSNET` is attached to OPSA; `pd-OPSWEB-0` should therefore show
  that VRF. `OPSOFF` is intentionally disabled and exercises disabled-service
  reporting; it is not expected to have a running Podman object.
- **NAT:** TCP entering veth60 for `10.60.10.1:8080` is translated to
  `10.60.40.10:8080` on OPSWEB.
  The source is masqueraded when leaving for the container. The HTTP command in
  `traffic.txt` exercises both translations from OPSB through the BGP route.
- **Firewall:** both families have per-source meter keys, inline quotas, a shared
  quota/counter, learned address/match groups, static groups, maps, ICMP groups,
  named limits, raw hooks, a flowtable and zone dispatch tables. Observation rules
  continue evaluation, so the test quota/limit matches do not impose a final drop.
- **NTP/DNS:** public DNS and `pool.ntp.org` supply upstream lookups and time.
  Internet reachability is needed for usable results; it is not created by this lab.
- **Sessions/system:** the existing SSH login populates `show users`. A second
  SSH session provides another row. CPU, memory, storage, processes and service
  health report the router's actual state without fabricated test data.

## Expected empty or unsupported views

Run `traffic.txt` before inspecting learned members, quota consumption, limit
keys, NAT translations and NTP clients. Re-run its requests if entries expire.
The self-contained DHCPv4 lease and BGP peers should populate without additional
machines. Physical-port leases require a client/cable, and unplugged DHCP
listeners may report that they are waiting for carrier.

Some Ethernet drivers, especially virtual NICs, cannot supply optical transceiver,
ring/channel or vendor statistics. Their unsupported/unavailable output is a
useful result, not evidence that the example configuration is incomplete.

`show firewall fail-safe` should normally report **inactive**. Its configuration
is retained for startup; the main firewall removes its table during handover.
Use the regular configuration display to inspect the stored fail-safe policy.

`clear conntrack` in `actions.txt` affects all connections, including SSH and NAT,
and prompts for confirmation. Test it last. No general log commands are included.

## Validation

The configuration was parsed through the current CLI and run through the real
configuration verification/generation paths with host mutations and host inventory
queries replaced by test doubles. Operational commands were resolved to executable
schema endpoints. This example has not been deployed as a complete lab to the live
router; carrier, external DHCPv6 clients, upstream time/DNS and hardware diagnostics
remain dependent on that environment.
