bond:
  kind: node
  description: Bond carrier, mode and members
  command: ['bond.nvyr.op', 'show']
  children:

    bond-name:
      kind: tag_node
      positional: true
      description: Bond carrier, mode and members
      validators:
        regex: {pattern: 'bond[0-9]+'}
      hints:
        bondN: Bond interface
      suggestors:
        config-path: {path: 'interfaces bond'}
      command: ['bond.nvyr.op', 'show', '--bond', '@4']
      children:

        lacp:
          kind: node
          description: Actor and partner forwarding state for each bond member
          command: ['bond.nvyr.op', 'show', '--bond', '@4', '--section', 'lacp']
          children:

            detail:
              kind: leaf_node
              valueless: true
              description: Actor and partner system IDs, port settings and full LACP state
              command: ['bond.nvyr.op', 'show', '--bond', '@4', '--section', 'lacp', '--detail']

        member:
          kind: tag_node
          description: Member link state, speed and failures
          command: ['bond.nvyr.op', 'show', '--bond', '@4', '--member', '@6']
          validators:
            regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
          hints:
            interface: Member interface name
          suggestors:
            bond-members: {}
