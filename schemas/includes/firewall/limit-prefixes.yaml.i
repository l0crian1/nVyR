children: # limit subnet keys

  source-prefix-length:
    kind: leaf_node
    description: Share an allowance within each source subnet; requires per source-address
    validators:
      integer-range: {minimum: 0, maximum: 128}
    hints:
      length: IPv4 prefix length 0-32 or IPv6 prefix length 0-128

  destination-prefix-length:
    kind: leaf_node
    description: Share an allowance within each destination subnet; requires per destination-address
    validators:
      integer-range: {minimum: 0, maximum: 128}
    hints:
      length: IPv4 prefix length 0-32 or IPv6 prefix length 0-128
