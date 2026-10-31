children:

  access-list:
    kind: node
    description: Installed routing access-lists
    command: ['policy.nvyr.op', 'show', '@line']
    children:

      name:
        kind: tag_node
        positional: true
        description: Show one access-list
        command: ['policy.nvyr.op', 'show', '@line']
        validators:
          regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'}
        hints:
          name: Access-list name
        suggestors:
          config-path: {path: 'policy access-list ipv4'}

  prefix-list:
    kind: node
    description: Installed prefix-lists
    command: ['policy.nvyr.op', 'show', '@line']
    children:

      summary:
        kind: node
        description: Prefix-list summary
        command: ['policy.nvyr.op', 'show', '@line']
        children:

          name:
            kind: tag_node
            positional: true
            description: Summarize one prefix-list
            command: ['policy.nvyr.op', 'show', '@line']
            validators:
              regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'}
            hints:
              name: Prefix-list name
            suggestors:
              config-path: {path: 'policy prefix-list ipv4'}

      detail:
        kind: node
        description: Prefix-list entries and counters
        command: ['policy.nvyr.op', 'show', '@line']
        children:

          name:
            kind: tag_node
            positional: true
            description: Inspect one prefix-list in detail
            command: ['policy.nvyr.op', 'show', '@line']
            validators:
              regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'}
            hints:
              name: Prefix-list name
            suggestors:
              config-path: {path: 'policy prefix-list ipv4'}

      name:
        kind: tag_node
        positional: true
        description: Show one prefix-list
        command: ['policy.nvyr.op', 'show', '@line']
        validators:
          regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'}
        hints:
          name: Prefix-list name
        suggestors:
          config-path: {path: 'policy prefix-list ipv4'}
        children:

          seq:
            kind: tag_node
            description: Show one sequence number
            command: ['policy.nvyr.op', 'show', '@line']
            validators:
              integer-range: {minimum: 1, maximum: 4294967295}
            hints:
              number: Prefix-list sequence number

          prefix:
            kind: tag_node
            positional: true
            description: Inspect entries for a prefix
            command: ['policy.nvyr.op', 'show', '@line']
            validators:
              ipv4-prefix: {}
            hints:
              x.x.x.x/x: IPv4 prefix
            children:

              longer:
                kind: node
                description: Show matching longer prefixes
                command: ['policy.nvyr.op', 'show', '@line']

              first-match:
                kind: node
                description: Show the first matching prefix-list entry
                command: ['policy.nvyr.op', 'show', '@line']
