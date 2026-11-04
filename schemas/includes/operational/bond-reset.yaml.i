reset:
  kind: node
  description: Change runtime selection
  access: net-admin
  children:

    interfaces:
      kind: node
      description: Interface runtime controls
      children:

        bond:
          kind: tag_node
          description: Select an active bond member
          validators:
            regex: {pattern: 'bond[0-9]+'}
          hints:
            bondN: Bond interface name
          suggestors:
            config-path: {path: 'interfaces bond'}
          children:

            active-member:
              kind: leaf_node
              description: Switch the active member until the next failover
              command: ['bond.nvyr.op', 'select', '@4', '@6']
              validators:
                regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
              hints:
                interface: Member interface name
              suggestors:
                bond-members: {}
