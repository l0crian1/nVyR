packet-length:
  kind: leaf_node
  multi: true
  negatable: true
  description: Packet length in bytes including the IP header, as seen by the kernel
  validators:
    integer-range: {minimum: 0, maximum: 4294967295, allow_range: true}
  hints:
    bytes: Packet length in bytes
    start-end: Inclusive byte range
