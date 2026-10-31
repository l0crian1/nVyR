route-map:
  kind: node
  access: net-admin
  description: Reset installed route-map statistics
  children:

    counters:
      kind: node
      description: Clear counters for all route-maps
      command: ['policy.nvyr.op', 'clear', '@line']
      children:

        name:
          kind: tag_node
          positional: true
          description: Clear counters for one route-map
          command: ['policy.nvyr.op', 'clear', '@line']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'}
          hints:
            name: Route-map name
          suggestors:
            config-path: {path: 'policy route-map'}
