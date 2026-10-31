jump-target:
  kind: leaf_node
  description: Named chain to evaluate when action is jump
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Existing named chain in the same address family
