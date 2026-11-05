# LLDP discovery

LLDP advertises this router to directly connected neighbors and displays the
information they advertise. Configure it under `service lldp`; without that
section, nVyR does not run LLDP.

## Select interfaces

Enable LLDP on all interfaces eligible for native discovery:

```text
set service lldp interface all
```

Or select individual names and prefixes. Quote patterns when entering commands
from a Linux shell:

```text
set service lldp interface 'eth*'
set service lldp exclude-interface eth0
set service lldp interface eth2 port-description 'Core switch uplink'
```

lldpd matches patterns itself, including interfaces that appear later. Exclusions
win over inclusions. `all` means the daemon's eligible interfaces, not every Linux
device: native discovery normally selects physical Ethernet links. An exact name
can explicitly select a virtual Ethernet or VLAN interface.

An `all` or wildcard entry must have no settings beneath it. Exact names may have
overrides alongside `all` or a wildcard selector. Overrides require an available,
eligible interface when applied. They cannot be attached to an excluded port.

## Advertisements and port overrides

```text
set service lldp system-name edge-router
set service lldp system-description 'Home edge router'
set service lldp management-interface eth1
set service lldp transmit-interval 10 hold-multiplier 4
set service lldp port-id interface-name
set service lldp interface eth2 port-id core-uplink
set service lldp interface eth2 mode receive-only
```

Global `mode` and `port-description` apply to ports without overrides. Modes are
`receive-transmit`, `receive-only`, and `transmit-only`. Per-port `disable` stops
both directions and cannot accompany `mode`. Global `disable` stops the service.

For tagged advertisements:

```text
set service lldp interface eth2 transmit-vlan 123 priority 5
```

There is one transmit VLAN per port. VLAN 0 requests priority tagging; `dei` sets
the drop eligible bit. Removing the setting returns to untagged advertisements.

Other settings include:

- `chassis-id` for a custom local identifier, or `chassis-interface` to select the
  interfaces used to derive it. These choices are mutually exclusive.
- `management-address` and `management-interface` to build lldpd's management
  address selection pattern. Inspect `show lldp local` to see the selected addresses.
- `capability` to override enabled capabilities supported by this host. The native
  daemon limits them to its supported capability bitmap.
- `disable-capability-advertisement` and
  `disable-management-address-advertisement` to omit those advertisements.
- `max-neighbors`, `agent-type`, and `bond-member-source-mac` for native LLDP
  behavior. Agent types select the nearest bridge, nearest non-TPMR bridge, or
  nearest customer bridge multicast scope.

Omitted values retain lldpd defaults: transmit and receive, a 30-second interval,
hold multiplier 4, and 32 neighbors per interface per protocol. A configuration
change restarts LLDP to reliably remove old overrides, briefly resetting its
neighbor cache and counters. An unrelated commit with unchanged LLDP settings
does not restart it.

## Inspect neighbors

```text
show lldp neighbors
show lldp neighbors interface eth2 detail
show lldp interfaces
show lldp interfaces eth2 detail
show lldp local
show lldp statistics interface eth2
monitor lldp interface eth2
show log lldp
```

Summary displays use tables; `detail` retains the complete native information,
including additional TLVs advertised by neighbors. `monitor` runs until interrupted.
Finite show commands support normal output filters such as `| match`.

See the [command tree](command-tree.md) for all choices and ranges, and the
[implementation guide](../dev/lldp.md) for lifecycle and test details.
