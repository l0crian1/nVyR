# Interface diagnostics

For implementation and testing, see the [developer guide](../dev/interface-operations.md).

## Summary and detail

```text
show interfaces
show interfaces eth0
show interfaces eth0 detail
show interfaces eth0 statistics
```

The summary shows interface, addresses, MAC, VRF, MTU, state/link and description.
VRF membership follows the live kernel relationships; container veth interfaces
inherit the VRF of their bridge. The `statistics` view reports kernel traffic
counters.
`show interfaces <interface> detail` also shows link-group and link-local IPv6
addresses. VLAN interfaces include their parent, tag and protocol; veth interfaces
include the peer name when it is in the same network namespace. Remote peers are
identified by index and namespace status, without resolving an unrelated local
interface with the same index.

Physical Ethernet detail includes speed, duplex, autonegotiation, supported and
advertised link modes, peer-advertised modes, port medium, and an extended link
diagnosis when reported. Modes retain medium and duplex information rather than
collapsing distinct capabilities with the same speed. Available pause settings,
negotiated pause, configured/active FEC, EEE status, driver, firmware and bus
information follow. Unknown speed is never displayed as zero or a fabricated rate.

## Focused views

```text
show interfaces eth0 offload
show interfaces eth0 queues
show interfaces eth0 hardware-statistics
show interfaces eth0 transceiver
```

- `offload`: all reported features and their active state.
- `queues`: current/maximum RX, TX, other and combined channel counts, followed
  by current/maximum ring sizes. Either category may be independently unsupported.
- `hardware-statistics`: exact driver-provided counter names and integer values.
  These are distinct from the generic kernel counters in `statistics`.
- `transceiver`: decoded module fields, including vendor/part/serial information,
  measurements and alarms where available. Multiple optical lanes remain distinct.
  `strip-private` and `strip-private partial` mask module serial identifiers.

Use the privacy modifier on summary, detail, raw, or hardware views:

```text
show interfaces | strip-private
show interfaces eth0 detail | strip-private partial
show interfaces | strip-private public
```

`partial` displays addresses such as `10.5.xxx.xxx/24` and
`2001:db8:x:x:x:x:x:x/64`, and MACs such as `02:11:22:xx:xx:xx`.
Descriptions remain fully masked. `public` masks only globally routable unicast
IP addresses, retaining non-public addresses, MACs, descriptions, and serials.
Bare `strip-private` and `strip-private all` retain full masking.

The existing `show interfaces ethernet eth0 ...` selector also supports these
views. Omitting the interface queries physical Ethernet interfaces; an explicit
interface can query a virtual device that supports the requested diagnostics.
All commands are read-only and available to operators. They do not run cable
tests, reset counters, or change link settings.

## Unavailable hardware information

Unsupported hardware and absent optional data do not prevent display. Actual
permission, I/O, missing-device, malformed-response and command failures are
reported in focused diagnostic commands. The detailed link view omits unsupported
optional categories; focused views explicitly report unavailable data. Driver support determines which
information exists; a virtual Ethernet device's reported rate is not a physical
negotiated link speed, so virtual interface detail does not query Ethernet modes.

In `detail`, failed diagnostics produce one `Ethernet diagnostics: Currently
unavailable` note instead of raw error text or an aborted display. Missing detail
values are blank; valid fields from partial ethtool responses are retained,
including when ethtool reports errors on stderr with exit status zero. Some
drivers, including `r8169`, cannot return link settings while administratively
down. Viewing an interface never brings it up or requires configuring it first.

## VRF inventory

```text
show vrf
show vrf BLUE
```

Both commands use the same table: Name, State, MAC address and Interfaces.
Interfaces lists directly attached kernel members, or `n/a` when there are none.
State is administrative up/down, since a Linux VRF commonly reports an unknown
operational link state. The table lists actual VRF devices, not a synthetic row
for the default routing domain. An unknown requested VRF reports an error;
an empty inventory reports that no VRFs are configured.

See [VRF configuration](interfaces.md#vrfs-and-link-groups) for creating VRFs
and attaching interfaces.
