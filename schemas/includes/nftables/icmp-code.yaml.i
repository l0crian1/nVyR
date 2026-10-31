icmp-code:
  kind: leaf_node
  multi: true
  description: Match ICMP code
  validators:
    integer-range: {minimum: 0, maximum: 255}
  hints:
    0-255: Individual numeric ICMP code
