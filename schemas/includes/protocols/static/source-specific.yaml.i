source-specific:
  kind: node
  description: IPv6 routes matching both destination and source prefixes
  children: # source-specific

    from:
      kind: tag_node
      strip_kind: ipv6
      description: Source prefix for this IPv6 route
      validators:
        network: {version: 6}
      hints:
        x:x:x:x:x:x/x: IPv6 source network with prefix length
      children: # from

        include_schema:
        - file: protocols/static/route-options.yaml.i
          as: null
        - file: protocols/static/next-hop6.yaml.i
