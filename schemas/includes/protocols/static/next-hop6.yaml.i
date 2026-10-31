next-hop:
  kind: tag_node
  strip_kind: ipv6
  description: IPv6 next-hop address
  validators:
    ipv6-address: {}
  hints:
    x:x:x:x:x:x: IPv6 next-hop address
  children: # next-hop

    include_schema:
    - file: protocols/static/gateway-options.yaml.i
      as: null
