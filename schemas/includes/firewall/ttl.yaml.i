ttl:
  kind: node
  description: IPv4 TTL or IPv6 hop-limit comparison
  children: # ttl

    eq:
      kind: leaf_node
      negatable: true
      description: Equal to the specified TTL or hop limit
      validators:
        integer-range: {minimum: 0, maximum: 255}
      hints:
        0-255: TTL or hop-limit value

    lt:
      kind: leaf_node
      description: Less than the specified TTL or hop limit
      validators:
        integer-range: {minimum: 0, maximum: 255}
      hints:
        0-255: TTL or hop-limit value

    gt:
      kind: leaf_node
      description: Greater than the specified TTL or hop limit
      validators:
        integer-range: {minimum: 0, maximum: 255}
      hints:
        0-255: TTL or hop-limit value
