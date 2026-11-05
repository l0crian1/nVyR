ripng:
  kind: node
  description: RIPNG routes
  command:
  - 'rip.nvyr.op'
  - 'show'
  - '@line'
  children:

    status:
      kind: node
      description: Protocol timers, interfaces and routing sources
      command:
      - 'rip.nvyr.op'
      - 'show'
      - '@line'

    vrf:
      kind: tag_node
      description: Routing instance
      validators:
        regex:
          pattern: '[A-Za-z][A-Za-z0-9_.-]{0,14}'
      hints:
        vrf: Routing instance name
      choices:
        default: Default routing instance
        all: All routing instances
      suggestors:
        config-path:
          path: vrf name
      command:
      - 'rip.nvyr.op'
      - 'show'
      - '@line'
      children:

        status:
          kind: node
          description: Protocol timers, interfaces and routing sources
          command:
          - 'rip.nvyr.op'
          - 'show'
          - '@line'
