# Early firewall protection

For implementation and testing, see the [developer guide](../dev/firewall-failsafe.md).

`firewall fail-safe` holds an optional firewall configuration applied before
interface configuration during configd startup. It uses the ordinary firewall
syntax and verification, excluding ingress hooks, flowtables, `action offload`, `offload-target`,
and the global flowtable setting. Interface-name matches do not require the
interface to exist yet.

For example, allow SSH, loopback traffic and DHCP responses while blocking other
IPv4 input and forwarding:

```text
set firewall fail-safe ipv4 input filter default-action drop
set firewall fail-safe ipv4 input filter rule 10 action accept inbound-interface lo
set firewall fail-safe ipv4 input filter rule 20 action accept protocol tcp destination-port 22
set firewall fail-safe ipv4 input filter rule 30 action accept protocol udp source-port 67 destination-port 68

set firewall fail-safe ipv4 forward filter default-action drop
```

IPv6 can be configured independently. Allow ICMPv6 so neighbor discovery works:

```text
set firewall fail-safe ipv6 input filter default-action drop
set firewall fail-safe ipv6 input filter rule 10 action accept inbound-interface lo
set firewall fail-safe ipv6 input filter rule 20 action accept protocol tcp destination-port 22
set firewall fail-safe ipv6 input filter rule 30 action accept protocol ipv6-icmp

set firewall fail-safe ipv6 forward filter default-action drop

commit
save
```

These are explicit policies, not built-in restrictions. An absent fail-safe adds
no protection. An empty fail-safe adds an empty table; unconfigured hooks and
families are not implicitly dropped.

## Application and handover

- Fail-safe protection loads before VRFs and interfaces.
- The main firewall runs after interfaces and applies `nvyr_filter`, NAT and
  removal of `nvyr_filter_failsafe` in one nftables transaction. A rejected
  transaction leaves the previously installed fail-safe intact.
- Startup follows the existing recovery error handling; this feature adds no
  interface activation barrier.
- A commit after handover validates and stores fail-safe changes for the next
  startup. It does not reactivate the table. Ordinary rollback behaves likewise.
- If the fail-safe is still active, changing it replaces its entire table in one
  transaction. Deleting it removes that table. Its temporary counters and learned
  state are not retained across replacement or handover.
- Use `save` to retain the configuration across reboot.

`show firewall fail-safe` displays the installed temporary rules and groups;
`show firewall fail-safe detail` uses detailed output. After handover, both report
that the fail-safe is not active. Configuration remains visible through the usual
configuration display commands.

## Shared objects and references

Groups, maps, zones and named chains belong to the fail-safe subtree. Their names
may overlap main-firewall names because they inhabit separate nftables tables.
Suggestions use the fail-safe configuration. Interface/VRF context still comes
from the shared effective configuration.

References within fail-safe do not block deletion while editing, but
commit rejects unresolved local references. There is no automatic reapply from interface changes: the table exists
only for the early startup phase, with a complete replacement when needed.

GeoIP selectors and domain-groups are excluded from fail-safe configuration.
They depend on external data and DNS, while this table loads before interfaces.
Use configured address-groups for early protection instead. The system DNS script
runs after interface configuration and before the main firewall.
