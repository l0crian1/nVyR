limit:
  kind: node
  anchor: true
  description: Match when the tracked connection count exceeds a threshold
  children: # limit

    include_schema:
    - file: firewall/limit-per.yaml.i
      replace:
        /choices/source-address: Packet source IPv4 or IPv6 address
        /choices/destination-address: Packet destination IPv4 or IPv6 address
    - file: firewall/limit-prefixes.yaml.i
      as: null

    over:
      kind: leaf_node
      description: Match when more than this many connections are tracked
      validators:
        integer-range: {minimum: 0, maximum: 4294967295}
      hints:
        0-4294967295: Match when more than this many connections are tracked (decimal)

    size:
      kind: leaf_node
      description: Maximum per-key connection counters (default 65536; requires per)
      validators:
        integer-range: {minimum: 1, maximum: 4294967295}
      hints:
        1-4294967295: Maximum per-key connection counters (default 65536; requires per) (decimal)
