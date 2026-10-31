route6:
  kind: tag_node
  strip_kind: ipv6
  anchor: true
  description: IPv6 static network route
  validators:
    network: {version: 6}
  hints:
    x:x:x:x:x:x/x: IPv6 destination network with prefix length
  children: # route6

    include_schema:
    - file: protocols/static/route-options.yaml.i
      as: null
    - file: protocols/static/next-hop6.yaml.i
    - file: protocols/static/source-specific.yaml.i
