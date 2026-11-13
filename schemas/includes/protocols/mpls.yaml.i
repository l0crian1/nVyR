mpls:
  kind: node
  description: MPLS kernel forwarding
  anchor: true
  children:

    interface:
      kind: leaf_node
      multi: true
      description: Accept labeled packets on this interface
      validators:
        regex: {pattern: '[A-Za-z][A-Za-z0-9_.-]{0,14}'}
      hints:
        interface: MPLS input interface
      suggestors:
        interfaces: {}

    label-table-size:
      kind: leaf_node
      description: Number of incoming label slots in the kernel
      validators:
        integer-range: {minimum: 16, maximum: 1048575}
      hints:
        16-1048575: Label-table capacity
      default: {mode: direct, value: '1048575'}
  script:
    name: mpls
    priority: 44
    watch-before:
    - interfaces
