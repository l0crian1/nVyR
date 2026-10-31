route:
  kind: node
  description: Routing table from FRR
  command: ['static.nvyr.op', 'show', '@line']
  children: # route

    include_schema:
    - file: operational/route-display-options.yaml.i
      as: null

    vrf:
      kind: tag_node
      description: Routing table for one or all VRFs
      command: ['static.nvyr.op', 'show', '@line']
      validators:
        regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
      suggestors:
        config-path: {path: 'vrf name'}
      choices:
        default: Default routing instance
        all: All routing instances
      hints:
        name: VRF name
      children: # vrf

        include_schema:
        - file: operational/route-display-options.yaml.i
          as: null

    table:
      kind: tag_node
      description: Routes in a routing table
      command: ['static.nvyr.op', 'show', '@line']
      validators:
        mode: OR
        integer-range: {minimum: 1, maximum: 4294967295}
        list: {values: all}
      choices:
        all: All routing tables
      hints:
        number: Routing table ID
      children: # table

        include_schema:
        - file: operational/route-destination.yaml.i
        - file: operational/route-selectors.yaml.i
          as: null

        static:
          kind: node
          description: Static routes in this table
          command: ['static.nvyr.op', 'show', '@line']
