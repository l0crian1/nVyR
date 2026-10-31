as-path-access-list:
  kind: node
  description: Installed AS-path access-list definitions
  command: ['policy.nvyr.op', 'show', '@line']
  children:

    name:
      kind: tag_node
      positional: true
      description: Show one AS-path access-list
      command: ['policy.nvyr.op', 'show', '@line']
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'}
      hints:
        name: AS-path list name
      suggestors:
        config-path: {path: 'policy as-path-list'}
