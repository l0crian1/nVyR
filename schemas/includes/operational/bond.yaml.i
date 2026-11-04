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
          kind: leaf_node
          valueless: true
          description: Local and partner LACP negotiation by port
          command: ['bond.nvyr.op', 'show', '--bond', '@4', '--section', 'lacp']

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
