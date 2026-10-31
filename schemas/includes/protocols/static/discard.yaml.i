children: # discard paths (shared)

  blackhole:
    kind: node
    description: Silently discard traffic for this route
    children: # blackhole

      include_schema:
      - file: protocols/static/path-options.yaml.i
        as: null

  reject:
    kind: node
    description: Reject traffic with an ICMP unreachable response
    children: # reject

      include_schema:
      - file: protocols/static/path-options.yaml.i
        as: null
