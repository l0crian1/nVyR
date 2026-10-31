children: # group entry fields

  include_schema:
  - file: firewall/connection-entry_ipv4.yaml.i
  - file: nftables/icmp-type.yaml.i
    replace:
      /multi: false
  - file: nftables/icmp-code.yaml.i
    replace:
      /multi: false
  - file: firewall/group-entry.yaml.i
    as: null

  source-address:
    kind: leaf_node
    strip_kind: ipv4
    description: Source IPv4 address, prefix or range
    validators:
      mode: OR
      address: {version: 4}
      ip-range: {version: 4}
    hints:
      x.x.x.x[/x]: Source address or prefix
      start-end: Inclusive address range

  destination-address:
    kind: leaf_node
    strip_kind: ipv4
    description: Destination IPv4 address, prefix or range
    validators:
      mode: OR
      address: {version: 4}
      ip-range: {version: 4}
    hints:
      x.x.x.x[/x]: Destination address or prefix
      start-end: Inclusive address range
