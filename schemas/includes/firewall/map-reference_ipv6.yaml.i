map:
  kind: leaf_node
  depends: firewall-map-ipv6
  description: Map supplying this rule's lookup fields and result
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Existing IPv6 map
  suggestors:
    config-path: {path: 'firewall group map ipv6'}
