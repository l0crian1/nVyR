children:

  include_schema:
  - file: firewall/group-description.yaml.i

  protocol:
    kind: leaf_node
    description: Transport protocol whose tracking timeouts are overridden
    choices:
      tcp: Transmission Control Protocol
      udp: User Datagram Protocol
    validators:
      list: {values: tcp udp}
    hints:
      protocol: TCP or UDP; timeout states must belong to this protocol

  timeout:
    kind: node
    anchor: true
    description: Connection state lifetimes; omitted states inherit global settings
    children:

      syn-sent:
        kind: leaf_node
        description: TCP SYN sent lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      syn-received:
        kind: leaf_node
        description: TCP SYN received lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      established:
        kind: leaf_node
        description: Established TCP connection lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      fin-wait:
        kind: leaf_node
        description: TCP FIN wait lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      close-wait:
        kind: leaf_node
        description: TCP close wait lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      last-ack:
        kind: leaf_node
        description: TCP last acknowledgement lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      time-wait:
        kind: leaf_node
        description: TCP time wait lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      close:
        kind: leaf_node
        description: Closed TCP connection lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      unacknowledged:
        kind: leaf_node
        description: TCP data awaiting acknowledgement lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      max-retransmissions:
        kind: leaf_node
        description: TCP connection exceeding its retransmission threshold lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      unreplied:
        kind: leaf_node
        description: UDP connection without reply traffic lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)

      replied:
        kind: leaf_node
        description: UDP connection with reply traffic lifetime
        validators:
          duration: {maximum: 2147483}
        hints:
          duration: Whole duration in s, m, h or d (1–2147483 seconds)
