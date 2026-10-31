children: # rule (shared)

  include_schema:
  - file: generic/disable.yaml.i
    replace:
      /description: Disable this rule
  - file: nftables/protocol.yaml.i
  - file: nftables/rule-counter.yaml.i
  - file: nftables/last-used.yaml.i
  - file: nftables/log.yaml.i

  description:
    kind: leaf_node
    strip_kind: private
    description: Rule description (at most 121 characters and UTF-8 bytes)
    validators:
      mode: AND
      text: {}
      length: {maximum: 121}
      byte-length: {maximum: 121}
      regex: {pattern: '[^"]*'}
    hints:
      text: Rule description; quote spaces, no embedded double quotes

  source-port:
    kind: leaf_node
    description: Source transport port or range
    multi: true
    validators:
      port: {allow_range: true}
    hints:
      1-65535: Port number
      start-end: Inclusive ascending port range

  destination-port:
    kind: leaf_node
    description: Destination transport port or range
    multi: true
    validators:
      port: {allow_range: true}
    hints:
      1-65535: Port number
      start-end: Inclusive ascending port range

  inbound-interface:
    kind: leaf_node
    depends: interface
    description: Incoming interface name or prefix ending in *
    multi: true
    validators:
      interface-match: {}
    hints:
      name: Incoming interface name (may refer to an interface not yet created)
      prefix*: Match incoming interface names starting with this prefix
    suggestors:
      interfaces: {}

  outbound-interface:
    kind: leaf_node
    depends: interface
    description: Outgoing interface name or prefix ending in *
    multi: true
    validators:
      interface-match: {}
    hints:
      name: Outgoing interface name (may refer to an interface not yet created)
      prefix*: Match outgoing interface names starting with this prefix
    suggestors:
      interfaces: {}
