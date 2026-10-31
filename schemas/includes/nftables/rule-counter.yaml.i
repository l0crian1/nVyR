counter:
  kind: node
  anchor: true
  description: Count matching packets and bytes
  children: # counter

    group:
      kind: leaf_node
      description: Accumulate counts in a shared named counter
      depends: firewall-counter-group
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Counter group name
      suggestors:
        config-path: {path: 'firewall group counter-group'}
