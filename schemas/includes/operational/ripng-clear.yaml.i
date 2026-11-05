ripng:
  kind: node
  description: Clear learned RIPNG routes
  access: net-admin
  command:
  - 'rip.nvyr.op'
  - 'clear'
  - '@line'
  children:

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
      suggestors:
        config-path:
          path: vrf name
      command:
      - 'rip.nvyr.op'
      - 'clear'
      - '@line'

    all:
      kind: node
      description: Clear routes in every routing instance
      command:
      - 'rip.nvyr.op'
      - 'clear'
      - '@line'
