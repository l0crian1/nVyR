children: # group entry

  include_schema:
  - file: firewall/vlan.yaml.i
  - file: nftables/tcp-flags.yaml.i
    replace:
      /multi: false
      /description: TCP flag requirements for this entry
  - file: nftables/protocol.yaml.i
    replace:
      /multi: false

  description:
    kind: leaf_node
    strip_kind: private
    description: Entry description (entry name and description must fit a 128-byte comment)
    validators:
      mode: AND
      text: {}
      length: {maximum: 121}
      byte-length: {maximum: 121}
      regex: {pattern: '[^"]*'}
    hints:
      text: Entry description; quote spaces, no embedded double quotes

  inbound-interface:
    kind: leaf_node
    depends: interface
    description: Inbound interface
    validators:
      regex: {pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'}
    hints:
      name: Interface name
    suggestors:
      interfaces: {}

  outbound-interface:
    kind: leaf_node
    depends: interface
    description: Outbound interface
    validators:
      regex: {pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'}
    hints:
      name: Interface name
    suggestors:
      interfaces: {}

  source-mac:
    kind: leaf_node
    strip_kind: mac
    description: Source MAC address
    validators:
      mac: {unicast: false}
    hints:
      xx:xx:xx:xx:xx:xx: Ethernet address

  destination-mac:
    kind: leaf_node
    strip_kind: mac
    description: Destination MAC address
    validators:
      mac: {unicast: false}
    hints:
      xx:xx:xx:xx:xx:xx: Ethernet address

  source-port:
    kind: leaf_node
    description: Source port or range
    validators:
      port: {allow_range: true}
    hints:
      1-65535: Port number
      start-end: Inclusive port range

  destination-port:
    kind: leaf_node
    description: Destination port or range
    validators:
      port: {allow_range: true}
    hints:
      1-65535: Port number
      start-end: Inclusive port range

  packet-mark:
    kind: leaf_node
    description: Packet mark or range
    validators:
      integer-range: {minimum: 0, maximum: 4294967295, allow_range: true}
    hints:
      0-4294967295: Decimal value
      start-end: Inclusive range

  dscp:
    kind: leaf_node
    description: DSCP or range
    validators:
      integer-range: {minimum: 0, maximum: 63, allow_range: true}
    hints:
      0-63: Decimal value
      start-end: Inclusive range

  packet-type:
    kind: leaf_node
    description: Link-layer packet destination type
    validators:
      list: {values: broadcast host multicast other}
    choices:
      broadcast: Link-layer broadcast packet
      host: Packet addressed to this host
      multicast: Link-layer multicast packet
      other: Packet addressed to another host

  inbound-link-group:
    kind: leaf_node
    description: Inbound Linux interface link group
    validators:
      integer-range: {minimum: 0, maximum: 4294967295}
    hints:
      0-4294967295: Numeric Linux link group

  outbound-link-group:
    kind: leaf_node
    description: Outbound Linux interface link group
    validators:
      integer-range: {minimum: 0, maximum: 4294967295}
    hints:
      0-4294967295: Numeric Linux link group
