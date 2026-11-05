# DNS forwarding

nVyR uses Unbound to forward and cache DNS queries. Configure the default routing
instance under `service dns forwarding`, or use
`vrf name <name> service dns forwarding` for an independent VRF instance.
This does not change the router's own `system name-server` configuration.

## Listeners and clients

```text
set service dns forwarding listen-address 192.168.0.1
set service dns forwarding listen-address fd00::1

set service dns forwarding allow-from 192.168.0.0/24
set service dns forwarding allow-from fd00::/64

set service dns forwarding name-server 9.9.9.9
set service dns forwarding name-server 2620:fe::fe
```

The default port is 53 for both UDP and TCP. Without listener selections, Unbound
listens on IPv4 and IPv6 loopback. Without `allow-from`, only loopback clients are
allowed. Firewall policy still applies separately.

`listen-interface <interface>` follows addresses on that interface. If it has no
usable addresses yet, the service waits rather than listening somewhere else.
New or removed addresses cause that instance to restart. Explicit addresses and
interfaces must belong to the selected routing instance.

## Upstreams and conditional forwarding

```text
set service dns forwarding name-server 9.9.9.9 tls authentication-name dns.quad9.net

set service dns forwarding domain home.example name-server 10.0.0.2
set service dns forwarding domain 0.0.10.in-addr.arpa name-server 10.0.0.2
```

An upstream's `port` defaults to 53, or 853 when `tls` is configured. TLS requires
an authentication name and verifies the certificate using the system CA store.
Every upstream in the same forwarding domain must use the same transport;
different domains can independently use TLS or ordinary UDP/TCP.

The most specific domain suffix wins. Explicit conditional forwarding also
allows forwarding zones that Unbound otherwise handles locally, such as private
reverse zones. Upstreams in one group are alternatives selected by Unbound;
their configuration order is not a strict priority list.

```text
set service dns forwarding name-server-interface eth0

set service dns forwarding domain isp.example name-server-interface eth0
```

Interface selections use currently valid DHCPv4, DHCPv6 and RA-learned DNS
servers, independently of `system name-server` and `/etc/resolv.conf`. They do
not bind outgoing traffic to that interface. Use `source-address` and the VRF's
routing configuration to control the source and route.

Learned servers cannot be combined with TLS in the same forwarding group.
Learned addresses that would point back to this resolver are excluded and shown
in its status. Explicit self-forwarding is rejected during commit.

Without usable upstreams, uncached requests fail with SERVFAIL; local records
remain available. Direct recursive fallback is disabled unless you configure
`fallback-recursion`, either globally or for an individual forwarding domain.

## Local hostnames

```text
set service dns forwarding local-data static-host-mapping
set service dns forwarding local-data dhcp-leases
set service dns forwarding local-data ttl 60
```

Static records come from `system static-host-mapping`. DHCP records come from
active IPv4 and IPv6 address leases in the selected VRF, including configured
DHCP domain qualification and short aliases. This does not require
`update-hostfile`. Delegated prefixes are not host addresses and are omitted.

A, AAAA and PTR records are generated. `local-data disable-reverse` omits PTR
records. Static mappings are system-wide but are published into a resolver only
when explicitly selected. DHCP records remain scoped to their VRF.

Learned upstreams, lease records and interface addresses are refreshed about
every five seconds. Expired leases are withdrawn without removing another
family's still-valid record. Client caches may retain answers until their TTL
expires; this is normal DNS behavior.

## Cache and validation

```text
set service dns forwarding cache message-size 16m
set service dns forwarding cache rrset-size 32m
set service dns forwarding cache maximum-ttl 3600
set service dns forwarding cache maximum-negative-ttl 60

set service dns forwarding cache prefetch
set service dns forwarding cache prefetch-dnssec
set service dns forwarding cache serve-expired maximum-age 3600 reply-ttl 30 client-timeout 500
```

`serve-expired` permits stale answers while attempting refresh. `maximum-age`
limits the stale age (zero means unlimited); `client-timeout` is milliseconds
before returning a stale response, and `reply-ttl` is its advertised lifetime.
`domain <domain> disable-cache` bypasses answer caching for one forwarding group.

DNSSEC validation is enabled with a persistent, automatically maintained root
trust anchor. `dnssec disable` disables validation for the instance;
`dnssec insecure-domain <domain>` exempts a specific suffix. An exemption is
useful for deliberately unsigned internal namespaces beneath signed parents.

The `options` subtree exposes worker counts, socket/query limits, EDNS and UDP
sizes, TCP idle timeout, response minimisation, identity/version hiding and
QNAME minimisation. Unspecified tuning settings retain Unbound's defaults.
In particular, a valueless option that already matches a native default does
not invert that default when removed.

## Operations

```text
show dns forwarding
show dns forwarding upstreams
show dns forwarding statistics
show dns forwarding cache name example.org
show dns forwarding local-data

show dns forwarding vrf BLUE
show dns forwarding vrf BLUE upstreams

clear dns forwarding cache name example.org
clear dns forwarding cache domain example.org
clear dns forwarding cache all
clear dns forwarding statistics

show log dns forwarding
show log dns forwarding vrf BLUE follow
```

`cache name` selects an exact owner name; clearing a `domain` includes its
descendants. Statistics display does not reset counters. Cache output uses
Unbound's native diagnostic format.

Enable query/reply logging under `logging queries` and `logging replies` when
needed; these can produce substantial output. Files use the existing global log
rotation settings. Configure `system logging service dns-forwarding level` to
control the file collector's severity threshold.

Use `disable` to stop an instance while retaining its configuration. Static
configuration changes restart only the affected instance. Dynamic upstream and
record updates reload it while preserving compatible cache entries.
