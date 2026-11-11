isis:
  kind: node
  description: Reset IS-IS adjacencies
  access: net-admin
  children:

    neighbor:
      kind: node
      description: Reset all adjacencies in this routing instance
      command:
      - 'isis.nvyr.op'
      - 'clear'
      - '@line'
      access: net-admin
      children:

        name:
          kind: tag_node
          description: Reset a selected neighbor
          command:
          - 'isis.nvyr.op'
          - 'clear'
          - '@line'
          access: net-admin
          children: {}
          positional: true
          validators:
            regex:
              pattern: '[A-Za-z0-9_.-]{1,128}'
          hints:
            system-id: Reset a selected neighbor

    vrf:
      kind: tag_node
      description: Routing instance
      children:

        neighbor:
          kind: node
          description: Reset all adjacencies in this routing instance
          command:
          - 'isis.nvyr.op'
          - 'clear'
          - '@line'
          access: net-admin
          children:

            name:
              kind: tag_node
              description: Reset a selected neighbor
              command:
              - 'isis.nvyr.op'
              - 'clear'
              - '@line'
              access: net-admin
              children: {}
              positional: true
              validators:
                regex:
                  pattern: '[A-Za-z0-9_.-]{1,128}'
              hints:
                system-id: Reset a selected neighbor
      validators:
        regex:
          pattern: '[A-Za-z][A-Za-z0-9_.-]{0,14}'
      hints:
        vrf: Routing instance
      choices:
        default: Default routing instance
        all: All routing instances
      suggestors:
        config-path:
          path: vrf name
