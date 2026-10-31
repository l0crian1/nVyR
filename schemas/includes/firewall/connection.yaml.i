connection:
  kind: node
  anchor: true
  description: Match tracked connection metadata
  children:

    include_schema:
    - file: firewall/connection-limit.yaml.i
    - file: firewall/connection-status.yaml.i
      as: status
      add:
        /negatable: true
    - file: nftables/protocol.yaml.i
      add:
        /negatable: true

    state:
      kind: leaf_node
      negatable: true
      description: Connection tracking state
      multi: true
      choices:
        new: New connections
        established: Established connections
        related: Related connections
        invalid: Invalid connection tracking state
        untracked: Untracked packets
      validators:
        list:
          values: new established related invalid untracked

    direction:
      kind: leaf_node
      description: Direction of this packet within its connection
      multi: true
      negatable: true
      validators:
        list:
          values: original reply
      hints:
        direction: Original or reply direction of the tracked connection
      choices:
        original: Original direction
        reply: Reply direction

    family:
      kind: leaf_node
      description: Network protocol of the tracked connection
      multi: true
      negatable: true
      validators:
        list:
          values: ipv4 ipv6
      hints:
        family: IPv4 or IPv6 family of the tracked connection
      choices:
        ipv4: IPv4 connection
        ipv6: IPv6 connection

    mark:
      kind: leaf_node
      description: Connection mark
      multi: true
      negatable: true
      validators:
        integer-range:
          minimum: 0
          maximum: 4294967295
          allow_range: true
      hints:
        0-4294967295: Connection mark (decimal)
        start-end: Inclusive ascending range; for example 10-20

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

    id:
      kind: leaf_node
      description: Transient kernel connection identifier
      multi: true
      negatable: true
      validators:
        integer-range:
          minimum: 0
          maximum: 4294967295
          allow_range: true
      hints:
        0-4294967295: Transient kernel connection identifier (decimal)
        start-end: Inclusive ascending range; for example 10-20

    helper:
      kind: leaf_node
      description: Assigned connection-tracking helper name
      multi: true
      negatable: true
      validators:
        regex:
          pattern: '[A-Za-z0-9_-]{1,15}'
      hints:
        name: Assigned conntrack helper name, 1-15 letters, digits, underscores or hyphens; for example ftp

    label:
      kind: leaf_node
      description: Connection-label bit positions; and requires all, repeated values are alternatives
      multi: true
      negatable: true
      validators:
        connection-label: {}
      hints:
        0-127: Connection-label bit positions; and requires all, repeated values are alternatives
      joinable: true

    expiration:
      kind: node
      anchor: true
      description: Remaining connection lifetime; use s, m, h or d
      children:

        eq:
          kind: leaf_node
          description: Equal to remaining connection lifetime; use s, m, h or d
          validators:
            connection-quantity:
              kind: expiration
          hints:
            duration: Remaining lifetime in s, m, h or d; for example 30s (maximum 4294967 seconds)
          negatable: true

        lt:
          kind: leaf_node
          description: Less than remaining connection lifetime; use s, m, h or d
          validators:
            connection-quantity:
              kind: expiration
          hints:
            duration: Remaining lifetime in s, m, h or d; for example 30s (maximum 4294967 seconds)

        gt:
          kind: leaf_node
          description: Greater than remaining connection lifetime; use s, m, h or d
          validators:
            connection-quantity:
              kind: expiration
          hints:
            duration: Remaining lifetime in s, m, h or d; for example 30s (maximum 4294967 seconds)

    original:
      kind: node
      anchor: true
      description: Inspect the stored original direction
      children:

        include_schema:
        - file: firewall/connection-direction.yaml.i
          as: null

    reply:
      kind: node
      anchor: true
      description: Inspect the stored reply direction
      children:

        include_schema:
        - file: firewall/connection-direction.yaml.i
          as: null

    total:
      kind: node
      anchor: true
      description: Accounting across both connection directions
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
