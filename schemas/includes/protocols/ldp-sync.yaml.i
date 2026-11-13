ldp-sync:
  kind: node
  description: Synchronize IGP reachability with LDP
  anchor: true
  children:

    hold-down:
      kind: leaf_node
      description: Maximum synchronization wait in seconds
      validators:
        integer-range: {minimum: 1, maximum: 10000}
      hints:
        1-10000: Maximum synchronization wait
