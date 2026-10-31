route:
  kind: tag_node
  strip_kind: ipv4
  anchor: true
  description: IPv4 static network route
  validators:
    network: {version: 4}
  hints:
    x.x.x.x/x: IPv4 destination network with prefix length
  children: # route

    include_schema:
    - file: protocols/static/route-options.yaml.i
      as: null
    - file: protocols/static/next-hop.yaml.i
