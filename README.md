# nVyR

**Not Vyatta Router**, pronounced **Never**.

nVyR is a Debian-based router operating system with a structured command-line
interface, candidate configuration, and integrated network services. It aims to avoid the 
inherited technical debt of creating a Vyatta fork based on a release that is more than a 
decade old.

The project is under active development and has not yet reached a production release.

Browse the [documentation](docs/README.md), start with [using the CLI](docs/users/cli.md),
or consult the complete [command tree](docs/users/command-tree.md).

## Current features

- Candidate configuration, validation, commit-confirm, rollback, and revision history
- Configuration import/export, draft sessions, and session locking
- Tab completion, contextual help, and anchored commands
- [Ethernet, loopback, dummy, virtual Ethernet, and VLAN interfaces](docs/users/interfaces.md)
- [Bridges, VLAN filtering, and spanning tree](docs/users/bridges.md)
- VRFs and interface link groups
- Static IPv4/IPv6 addressing and DHCPv4 clients
- [IPv4/IPv6 static routing](docs/users/static.md)
- [IPv4/IPv6 unicast BGP](docs/users/bgp.md)
- [Access lists, prefix-lists, route-maps, community lists, and AS-path lists](docs/users/routing-policy.md)
- [IPv4/IPv6 stateful](docs/users/firewall.md) and [zone-based firewall](docs/users/firewall-zones.md)
- Firewall groups, [maps](docs/users/firewall-maps.md), and [match-groups](docs/users/firewall-match-groups.md)
- Dynamic firewall groups, [GeoIP filtering](docs/users/firewall-geoip.md), and [DNS domain groups](docs/users/firewall-domain-groups.md)
- Firewall logging, flow offload, rate limits, connection limits, quotas, and counters
- [Early-boot fail-safe firewall](docs/users/firewall-failsafe.md)
- [IPv4 source NAT, destination NAT, masquerading, and port translation](docs/users/nat.md)
- [DHCPv4/DHCPv6 servers with shared networks, reservations, and VRF support](docs/users/dhcp-server.md)
- [DNS resolver configuration](docs/users/dns.md)
- [NTP client/server and NTS upstreams](docs/users/ntp.md)
- [SSH access](docs/users/ssh.md) and [role-based user permissions](docs/users/login.md)
- [Podman containers, pods, networks, and persistent volumes](docs/users/containers.md)
- [Operational commands and diagnostics](docs/users/command-tree.md)
- [Section-specific logs, NFLOG groups, and shared rotation](docs/users/logging.md)
- [BIOS/UEFI installation, multiple boot images, and persistent configuration](docs/users/installation.md)

## Build and install

Use the Docker build image to produce either the Debian package or a bootable
ISO. The current image target is **Debian 13 (trixie), amd64**.
Follow the [Docker build guide](docs/dev/debian.md), then the
[installation guide](docs/users/installation.md). [Serial console access](docs/users/serial-console.md)
is also available.

## Development and testing

- [Architecture](docs/dev/architecture.md)
- [Schema authoring](docs/dev/schema-builder.md) and [adding features](docs/dev/extending.md)
- [Python configuration API](docs/dev/config-session.md)
- [Live-system smoketests](smoketests/README.md)
- [Save/reboot acceptance tests](acceptance/README.md)
- [Upstream investigations](docs/dev/upstream-issues.md)

## License

nVyR's original code and documentation are licensed under the [MIT License](LICENSE).
Copyright (c) 2026 L0crian and nVyR contributors.

Third-party components retain their own licenses, including the GPL-licensed FRR
reload patch. See [third-party licensing and binary distribution requirements](THIRD_PARTY.md).
