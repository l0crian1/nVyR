dynamic:
  kind: node
  anchor: true
  description: Learn and refresh exact group members from firewall rules
  children: # dynamic

    timeout:
      kind: leaf_node
      description: Default lifetime refreshed by each packet update
      validators:
        duration: {maximum: 18446744073}
      hints:
        duration: Positive duration in s, m, h or d (maximum 18446744073 seconds)
      default:
        mode: direct
        value: '10m'

    size:
      kind: leaf_node
      description: Maximum number of packet-learned members
      validators:
        integer-range: {minimum: 1, maximum: 4294967295}
      hints:
        1-4294967295: Maximum group members
      default:
        mode: direct
        value: '65536'

    gc-interval:
      kind: leaf_node
      description: Interval between expired-member garbage collection runs
      validators:
        duration: {maximum: 4294967}
      hints:
        duration: Positive duration in s, m, h or d (maximum 4294967 seconds)
      default:
        mode: direct
        value: '30s'
