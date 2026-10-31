vlan:
  kind: node
  anchor: true
  description: Match the outer VLAN tag at ingress
  children:

    id:
      kind: leaf_node
      description: VLAN identifier
      validators:
        integer-range: {minimum: 0, maximum: 4095}
      hints:
        0-4095: VLAN identifier (including priority and reserved tags)

    priority:
      kind: leaf_node
      description: VLAN priority code point
      validators:
        integer-range: {minimum: 0, maximum: 7}
      hints:
        0-7: VLAN priority code point
