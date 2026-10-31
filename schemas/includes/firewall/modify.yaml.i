modify:
  kind: node
  anchor: true
  description: Change matching packets before this rule's verdict
  children:

    packet-mark:
      kind: leaf_node
      description: Replace the packet mark without requesting a new route lookup
      validators:
        firewall-mark: {}
      hints:
        0-4294967295: Unsigned 32-bit mark in decimal
        0x0-0xffffffff: Unsigned 32-bit mark in hexadecimal

    connection-mark:
      kind: leaf_node
      description: Replace the mark stored on the tracked connection
      validators:
        firewall-mark: {}
      hints:
        0-4294967295: Unsigned 32-bit mark in decimal
        0x0-0xffffffff: Unsigned 32-bit mark in hexadecimal

    dscp:
      kind: leaf_node
      description: Replace the differentiated services code point while preserving ECN
      validators:
        firewall-dscp: {}
      hints:
        0-63: Differentiated services code point in decimal
      choices:
        be: Best effort (0)
        le: Lower effort (1)
        cs0: Class selector 0 (0)
        cs1: Class selector 1 (8)
        cs2: Class selector 2 (16)
        cs3: Class selector 3 (24)
        cs4: Class selector 4 (32)
        cs5: Class selector 5 (40)
        cs6: Class selector 6 (48)
        cs7: Class selector 7 (56)
        af11: Assured forwarding class 1, low drop precedence (10)
        af12: Assured forwarding class 1, medium drop precedence (12)
        af13: Assured forwarding class 1, high drop precedence (14)
        af21: Assured forwarding class 2, low drop precedence (18)
        af22: Assured forwarding class 2, medium drop precedence (20)
        af23: Assured forwarding class 2, high drop precedence (22)
        af31: Assured forwarding class 3, low drop precedence (26)
        af32: Assured forwarding class 3, medium drop precedence (28)
        af33: Assured forwarding class 3, high drop precedence (30)
        af41: Assured forwarding class 4, low drop precedence (34)
        af42: Assured forwarding class 4, medium drop precedence (36)
        af43: Assured forwarding class 4, high drop precedence (38)
        va: Voice admit (44)
        ef: Expedited forwarding (46)

    ttl:
      kind: leaf_node
      description: Replace the IPv4 TTL or IPv6 hop limit at this hook
      validators:
        integer-range: {minimum: 0, maximum: 255}
      hints:
        0-255: New TTL or hop limit

    tcp-mss:
      kind: leaf_node
      description: Reduce an existing TCP MSS option on SYN or SYN-ACK packets
      validators:
        mode: OR
        integer-range: {minimum: 1, maximum: 65535}
        list: {values: clamp-to-pmtu}
      hints:
        1-65535: TCP maximum segment size in bytes
      choices:
        clamp-to-pmtu: Use the route MTU without increasing the advertised MSS
