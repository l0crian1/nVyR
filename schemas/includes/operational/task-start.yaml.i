start:
  kind: node
  description: Start managed operations
  children:

    system:
      kind: node
      description: System operations
      children:

        task:
          kind: tag_node
          access: net-admin
          description: Start an enabled task now
          hints:
            name: Configured task name
          suggestors:
            config-path: {path: system task}
          validators:
            regex: {pattern: '[A-Za-z0-9][A-Za-z0-9_-]{0,62}'}
          command: ['tasks.nvyr.op', 'start', '@4']
