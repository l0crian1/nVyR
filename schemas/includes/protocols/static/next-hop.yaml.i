next-hop:
  kind: tag_node
  strip_kind: ip
  description: IPv4 or IPv6 next-hop address
  validators:
    inet-address: {}
  hints:
    x.x.x.x: IPv4 next-hop address
    x:x:x:x:x:x: IPv6 next-hop address
  children: # next-hop

    include_schema:
    - file: protocols/static/gateway-options.yaml.i
      as: null
