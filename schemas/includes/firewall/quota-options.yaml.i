children: # quota options

  bytes:
    kind: leaf_node
    description: Cumulative byte allowance; optional k, m or g suffix
    validators:
      quota-bytes: {}
    hints:
      bytes: Whole bytes or short units, for example 100m or 10g

  over:
    kind: leaf_node
    valueless: true
    description: Match after the byte allowance is exceeded

  until:
    kind: leaf_node
    valueless: true
    description: Match while the byte allowance remains (default)
