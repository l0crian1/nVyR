mpls:
  kind: node
  description: MPLS forwarding and label allocation
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

    disable-ttl-propagation:
      kind: leaf_node
      description: Use pipe TTL behavior instead of copying the IP TTL
      valueless: true

    default-ttl:
      kind: leaf_node
      description: MPLS TTL when the IP TTL cannot be propagated
      validators:
        integer-range: {minimum: 1, maximum: 255}
      hints:
        1-255: MPLS TTL
      default: {mode: direct, value: '255'}

    fec:
      kind: node
      description: Forwarding equivalence class resolution
      children:

        nexthop-resolution:
          kind: leaf_node
          description: Allow recursive resolution of labeled BGP next hops
          valueless: true

    lsp:
      kind: tag_node
      anchor: true
      description: Static incoming-label forwarding entry
      validators:
        integer-range: {minimum: 16, maximum: 99999}
      hints:
        label: Incoming label
      children:

        description:
          kind: leaf_node
          description: Description of this static label
          hints:
            text: Description

        next-hop:
          kind: tag_node
          anchor: true
          description: Next hop in the default VRF
          validators:
            inet-address: {}
          hints:
            address: IPv4 or IPv6 next-hop address
          children:

            outgoing-label:
              kind: leaf_node
              description: Swap label or request explicit/implicit null
              validators:
                mpls-outgoing-label: {}
              hints:
                16-1048575: Outgoing label
              choices:
                explicit-null: Send an explicit-null label
                implicit-null: Pop the incoming label

  script:
    name: mpls
    priority: 39
    watch-before:
    - interfaces
