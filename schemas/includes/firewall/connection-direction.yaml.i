children:

  packets:
    kind: node
    anchor: true
    description: Tracked packet count
    children:

      eq:
        kind: leaf_node
        description: Equal to tracked packet count
        validators:
          connection-quantity:
            kind: packets
        hints:
          packets: Nonnegative whole packet count, up to 18446744073709551615
        negatable: true

      lt:
        kind: leaf_node
        description: Less than tracked packet count
        validators:
          connection-quantity:
            kind: packets
        hints:
          packets: Nonnegative whole packet count, up to 18446744073709551615

      gt:
        kind: leaf_node
        description: Greater than tracked packet count
        validators:
          connection-quantity:
            kind: packets
        hints:
          packets: Nonnegative whole packet count, up to 18446744073709551615

  bytes:
    kind: node
    anchor: true
    description: Tracked byte count; optional k, m or g
    children:

      eq:
        kind: leaf_node
        description: Equal to tracked byte count; optional k, m or g
        validators:
          connection-quantity:
            kind: bytes
        hints:
          bytes: Tracked byte count; nonnegative, optional binary k, m or g suffix, for example 64k
        negatable: true

      lt:
        kind: leaf_node
        description: Less than tracked byte count; optional k, m or g
        validators:
          connection-quantity:
            kind: bytes
        hints:
          bytes: Tracked byte count; nonnegative, optional binary k, m or g suffix, for example 64k

      gt:
        kind: leaf_node
        description: Greater than tracked byte count; optional k, m or g
        validators:
          connection-quantity:
            kind: bytes
        hints:
          bytes: Tracked byte count; nonnegative, optional binary k, m or g suffix, for example 64k

  average-packet-size:
    kind: node
    anchor: true
    description: Average tracked packet size in bytes; optional k, m or g
    children:

      eq:
        kind: leaf_node
        description: Equal to average tracked packet size in bytes; optional k, m or g
        validators:
          connection-quantity:
            kind: bytes
        hints:
          bytes: Average tracked packet size in bytes; nonnegative, optional binary k, m or g suffix, for example 64k
        negatable: true

      lt:
        kind: leaf_node
        description: Less than average tracked packet size in bytes; optional k, m or g
        validators:
          connection-quantity:
            kind: bytes
        hints:
          bytes: Average tracked packet size in bytes; nonnegative, optional binary k, m or g suffix, for example 64k

      gt:
        kind: leaf_node
        description: Greater than average tracked packet size in bytes; optional k, m or g
        validators:
          connection-quantity:
            kind: bytes
        hints:
          bytes: Average tracked packet size in bytes; nonnegative, optional binary k, m or g suffix, for example 64k

  zone:
    kind: leaf_node
    description: Conntrack zone
    multi: true
    negatable: true
    validators:
      integer-range:
        minimum: 0
        maximum: 65535
        allow_range: true
    hints:
      0-65535: Conntrack zone (decimal)
      start-end: Inclusive ascending range; for example 10-20

  source-address:
    kind: leaf_node
    description: Stored source address, prefix or range
    multi: true
    negatable: true
    validators:
      mode: OR
      address: {}
      ip-range: {}
    hints:
      address: Stored source address, prefix or range
    strip_kind: ip

  source-port:
    kind: leaf_node
    description: Stored source transport port or range
    multi: true
    negatable: true
    validators:
      integer-range:
        minimum: 0
        maximum: 65535
        allow_range: true
    hints:
      0-65535: Stored source transport port or range (decimal)
      start-end: Inclusive ascending range; for example 10-20

  destination-address:
    kind: leaf_node
    description: Stored destination address, prefix or range
    multi: true
    negatable: true
    validators:
      mode: OR
      address: {}
      ip-range: {}
    hints:
      address: Stored destination address, prefix or range
    strip_kind: ip

  destination-port:
    kind: leaf_node
    description: Stored destination transport port or range
    multi: true
    negatable: true
    validators:
      integer-range:
        minimum: 0
        maximum: 65535
        allow_range: true
    hints:
      0-65535: Stored destination transport port or range (decimal)
      start-end: Inclusive ascending range; for example 10-20
