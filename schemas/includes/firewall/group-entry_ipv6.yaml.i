children: # group entry fields

  include_schema:
  - file: firewall/connection-entry_ipv6.yaml.i
  - file: nftables/icmpv6-type.yaml.i
    replace:
      /multi: false
  - file: nftables/icmp-code.yaml.i
    replace:
      /multi: false
  - file: firewall/group-entry.yaml.i
    as: null

  source-address:
    kind: leaf_node
    strip_kind: ipv6
    description: Source IPv6 address, prefix or range
    validators:
      mode: OR
      address: {version: 6}
      ip-range: {version: 6}
    hints:
      x:x:x:x:x:x[/x]: Source address or prefix
      start-end: Inclusive address range

  destination-address:
    kind: leaf_node
    strip_kind: ipv6
    description: Destination IPv6 address, prefix or range
    validators:
      mode: OR
      address: {version: 6}
      ip-range: {version: 6}
    hints:
      x:x:x:x:x:x[/x]: Destination address or prefix
      start-end: Inclusive address range
