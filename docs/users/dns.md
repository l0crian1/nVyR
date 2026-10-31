# System DNS

For implementation and testing, see the [developer guide](../dev/dns.md).

Configure the DNS servers used by the router with `system name-server`:

```text
set system name-server 1.1.1.1
set system name-server 2606:4700:4700::1111

set system name-server eth0
set system name-server eth1

commit
save
```

An IP address selects a static resolver. An interface name selects DNS from its
current nVyR-managed DHCP lease; it does not enable DHCP on the interface. Configure
`set interfaces ethernet eth0 address dhcp` separately. Selectors can remain while
an interface is missing, disabled, unconfigured or awaiting a lease; they contribute
no servers until an enabled DHCP interface has a valid lease. Unselected interfaces
never contribute DNS. Removing the final name-server removes all upstream entries.

Static IPv4 and IPv6 servers come first, in configured order. Selected interfaces
follow in configured order, retaining each lease's advertised DNS order. Equivalent
addresses are deduplicated, including alternate IPv6 spellings. The current DHCP
client implements DHCPv4; this change does not add DHCPv6 or router-advertisement
DNS acquisition.

All aggregated servers are written, but resolver-library limits still apply:
[glibc's resolv.conf interface](https://man7.org/linux/man-pages/man5/resolv.conf.5.html)
uses at most three nameservers. This implementation does not start a local DNS
listener, provide forwarding, or add search domains.

## Inspection

```text
show system name-server

lookup example.com
lookup example.com type mx
lookup example.com server 1.1.1.1
lookup 192.0.2.10
```

`show system name-server` lists the currently published resolver addresses with
their Static/DHCP source and, for DHCP, the source interface and its current VRF.
That VRF identifies the source of the learned server; system resolver queries are
not bound to that VRF. Static servers use the default routing domain. Duplicates
retain the first contributing source, with static addresses taking precedence.
Failed publication and pending recovery are reported alongside the published list,
rather than displaying proposed servers as if they were active.

`lookup` requests A and AAAA by default. An IP address requests PTR automatically.
The optional `type` accepts `a`, `aaaa`, `mx`, `txt`, `ns`, `cname`, `soa`, `srv`,
`caa` and `ptr`. `server` selects an IPv4 or IPv6 DNS server without requiring a
configured system resolver. Answers show name, type, value and TTL in seconds,
followed by the responding server and elapsed query time. CNAME chains are retained.
The command distinguishes nonexistent names, missing record types, server errors
and timeouts. Each requested type has a five-second deadline; truncated UDP
answers retry over TCP. These commands support `run` from configuration mode.
