include_schema:
- file: firewall/connection.yaml.i
  replace:
    /children/state/multi: false
    /children/direction/multi: false
    /children/family/multi: false
    /children/mark/multi: false
    /children/zone/multi: false
    /children/id/multi: false
    /children/helper/multi: false
    /children/expiration:
      kind: leaf_node
      description: Remaining connection lifetime; use s, m, h or d
      validators:
        connection-quantity:
          kind: expiration
      hints:
        duration: Remaining lifetime in s, m, h or d; for example 30s (maximum 4294967 seconds)
    /children/original/children/packets:
      kind: leaf_node
      description: Tracked packet count
      validators:
        connection-quantity:
          kind: packets
      hints:
        packets: Nonnegative whole packet count, up to 18446744073709551615
    /children/original/children/bytes:
      kind: leaf_node
      description: Tracked byte count; optional k, m or g
      validators:
        connection-quantity:
          kind: bytes
      hints:
        bytes: Tracked byte count; nonnegative, optional binary k, m or g suffix, for example 64k
    /children/original/children/average-packet-size:
      kind: leaf_node
      description: Average tracked packet size in bytes; optional k, m or g
      validators:
        connection-quantity:
          kind: bytes
      hints:
        bytes: Average tracked packet size in bytes; nonnegative, optional binary k, m or g suffix, for example 64k
    /children/original/children/zone/multi: false
    /children/original/children/source-address/multi: false
    /children/original/children/source-port/multi: false
    /children/original/children/destination-address/multi: false
    /children/original/children/destination-port/multi: false
    /children/reply/children/packets:
      kind: leaf_node
      description: Tracked packet count
      validators:
        connection-quantity:
          kind: packets
      hints:
        packets: Nonnegative whole packet count, up to 18446744073709551615
    /children/reply/children/bytes:
      kind: leaf_node
      description: Tracked byte count; optional k, m or g
      validators:
        connection-quantity:
          kind: bytes
      hints:
        bytes: Tracked byte count; nonnegative, optional binary k, m or g suffix, for example 64k
    /children/reply/children/average-packet-size:
      kind: leaf_node
      description: Average tracked packet size in bytes; optional k, m or g
      validators:
        connection-quantity:
          kind: bytes
      hints:
        bytes: Average tracked packet size in bytes; nonnegative, optional binary k, m or g suffix, for example 64k
    /children/reply/children/zone/multi: false
    /children/reply/children/source-address/multi: false
    /children/reply/children/source-port/multi: false
    /children/reply/children/destination-address/multi: false
    /children/reply/children/destination-port/multi: false
    /children/total/children/packets:
      kind: leaf_node
      description: Tracked packet count
      validators:
        connection-quantity:
          kind: packets
      hints:
        packets: Nonnegative whole packet count, up to 18446744073709551615
    /children/total/children/bytes:
      kind: leaf_node
      description: Tracked byte count; optional k, m or g
      validators:
        connection-quantity:
          kind: bytes
      hints:
        bytes: Tracked byte count; nonnegative, optional binary k, m or g suffix, for example 64k
    /children/total/children/average-packet-size:
      kind: leaf_node
      description: Average tracked packet size in bytes; optional k, m or g
      validators:
        connection-quantity:
          kind: bytes
      hints:
        bytes: Average tracked packet size in bytes; nonnegative, optional binary k, m or g suffix, for example 64k
    /children/status/multi: false
    /children/status/hints:
      flag: Exact status flag; use and to combine flags for this entry
    /children/protocol/multi: false
  remove:
  - /children/limit
  - /children/label
  - /children/state/negatable
  - /children/direction/negatable
  - /children/family/negatable
  - /children/mark/negatable
  - /children/zone/negatable
  - /children/id/negatable
  - /children/helper/negatable
  - /children/original/children/zone/negatable
  - /children/original/children/source-address/negatable
  - /children/original/children/source-port/negatable
  - /children/original/children/destination-address/negatable
  - /children/original/children/destination-port/negatable
  - /children/reply/children/zone/negatable
  - /children/reply/children/source-address/negatable
  - /children/reply/children/source-port/negatable
  - /children/reply/children/destination-address/negatable
  - /children/reply/children/destination-port/negatable
  - /children/status/negatable
  - /children/protocol/negatable
