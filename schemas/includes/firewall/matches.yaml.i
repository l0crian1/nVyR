children: # firewall matches

  nftrace:
    kind: leaf_node
    valueless: true
    description: Trace matching packets through this and subsequent firewall rules

  include_schema:
  - file: nftables/tcp-flags.yaml.i
  - file: nftables/packet-length.yaml.i
  - file: firewall/fib.yaml.i
  - file: firewall/ttl.yaml.i

  packet-type:
    kind: leaf_node
    negatable: true
    description: Link-layer packet destination type
    choices:
      broadcast: Packet addressed to all hosts
      host: Packet addressed to this host
      multicast: Packet addressed to a multicast group
      other: Packet addressed to another host
    validators:
      list: {values: broadcast host multicast other}

  packet-mark:
    kind: leaf_node
    negatable: true
    description: Packet mark match
    multi: true
    validators:
      integer-range: {minimum: 0, maximum: 4294967295, allow_range: true}
    hints:
      0-4294967295: Packet mark (decimal)
      start-end: Inclusive ascending range

  dscp:
    kind: leaf_node
    negatable: true
    description: Differentiated services code point match
    multi: true
    validators:
      integer-range: {minimum: 0, maximum: 63, allow_range: true}
    hints:
      0-63: Differentiated services code point (decimal)
      start-end: Inclusive ascending range

  tcp-mss:
    kind: leaf_node
    negatable: true
    description: TCP maximum segment size match
    multi: true
    validators:
      integer-range: {minimum: 0, maximum: 65535, allow_range: true}
    hints:
      0-65535: TCP maximum segment size (decimal)
      start-end: Inclusive ascending range

  source-mac:
    kind: tag_node
    negatable: true
    strip_kind: mac
    description: Source Ethernet MAC address
    validators:
      mac: {unicast: false}
    hints:
      xx:xx:xx:xx:xx:xx: Source MAC address
    children: # source-mac

      mask:
        kind: leaf_node
        description: Bitmask selecting source MAC address bits to match
        validators:
          mac: {unicast: false}
        hints:
          xx:xx:xx:xx:xx:xx: MAC bitmask; requires exactly one source MAC address

  destination-mac:
    kind: tag_node
    negatable: true
    strip_kind: mac
    description: Destination Ethernet MAC address
    validators:
      mac: {unicast: false}
    hints:
      xx:xx:xx:xx:xx:xx: Destination MAC address
    children: # destination-mac

      mask:
        kind: leaf_node
        description: Bitmask selecting destination MAC address bits to match
        validators:
          mac: {unicast: false}
        hints:
          xx:xx:xx:xx:xx:xx: MAC bitmask; requires exactly one destination MAC address

  inbound-link-group:
    kind: leaf_node
    multi: true
    negatable: true
    description: Inbound Linux interface link group
    validators:
      integer-range: {minimum: 0, maximum: 4294967295}
    hints:
      0-4294967295: Numeric Linux link group

  outbound-link-group:
    kind: leaf_node
    multi: true
    negatable: true
    description: Outbound Linux interface link group
    validators:
      integer-range: {minimum: 0, maximum: 4294967295}
    hints:
      0-4294967295: Numeric Linux link group
