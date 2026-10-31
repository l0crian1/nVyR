static:
  kind: node
  description: Static routing state
  children: # static

    routes:
      kind: node
      description: Configured static routes and next-hop status from staticd
      command: ['static.nvyr.op', 'show', '@line']
      children: # routes

        vrf:
          kind: tag_node
          description: Static routes in one VRF
          command: ['static.nvyr.op', 'show', '@line']
          validators:
            regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
          suggestors:
            config-path: {path: 'vrf name'}
          choices:
            default: Default routing instance
          hints:
            name: VRF name
