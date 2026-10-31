route-map:
  kind: node
  description: Installed route-maps and usage counters from FRR
  command: ['policy.nvyr.op', 'show', '@line']
  children:

    name:
      kind: tag_node
      positional: true
      description: Show one installed route-map
      command: ['policy.nvyr.op', 'show', '@line']
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'}
      hints:
        name: Route-map name
      suggestors:
        config-path: {path: 'policy route-map'}
