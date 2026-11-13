ldp-sync:
  kind: node
  description: Override LDP synchronization on this interface
  anchor: true
  children:

    disable:
      kind: leaf_node
      valueless: true
      description: Disable synchronization on this interface

    hold-down:
      kind: leaf_node
      description: Maximum wait in seconds; zero waits indefinitely
      validators:
        integer-range: {minimum: 0, maximum: 10000}
      hints:
        0-10000: Maximum synchronization wait
