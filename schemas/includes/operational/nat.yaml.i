nat:
  kind: node
  description: Installed NAT rules and active translations
  children:
    translations:
      kind: node
      anchor: true
      description: Source and destination NAT translations
      command: ['conntrack.nvyr.op', 'show', '@line']
      children:
        include_schema:
        - file: operational/conntrack-filters.yaml.i
          as: null

    source:
      kind: node
      description: Installed source NAT rules
      command: ['nat.nvyr.op', 'show', '--direction', 'source']
      children:
        detail:
          kind: node
          description: Show all source NAT rule fields
          command: ['nat.nvyr.op', 'show', '--direction', 'source', '--detail']
        rule:
          kind: tag_node
          description: Select an installed source NAT rule
          validators:
            integer-range: {minimum: 1, maximum: 999999}
          hints:
            number: NAT rule number
          suggestors:
            config-path: {path: 'nat source rule'}
          command: ['nat.nvyr.op', 'show', '--direction', 'source', '--rule', '@5']
          children:
            detail:
              kind: node
              description: Show all fields for the selected rule
              command: ['nat.nvyr.op', 'show', '--direction', 'source', '--rule', '@5', '--detail']
        translations:
          kind: node
          anchor: true
          description: Connections with source NAT, including connections also using destination NAT
          command: ['conntrack.nvyr.op', 'show', '@line']
          children:
            include_schema:
            - file: operational/conntrack-filters.yaml.i
              as: null

    destination:
      kind: node
      description: Installed destination NAT rules
      command: ['nat.nvyr.op', 'show', '--direction', 'destination']
      children:
        detail:
          kind: node
          description: Show all destination NAT rule fields
          command: ['nat.nvyr.op', 'show', '--direction', 'destination', '--detail']
        rule:
          kind: tag_node
          description: Select an installed destination NAT rule
          validators:
            integer-range: {minimum: 1, maximum: 999999}
          hints:
            number: NAT rule number
          suggestors:
            config-path: {path: 'nat destination rule'}
          command: ['nat.nvyr.op', 'show', '--direction', 'destination', '--rule', '@5']
          children:
            detail:
              kind: node
              description: Show all fields for the selected rule
              command: ['nat.nvyr.op', 'show', '--direction', 'destination', '--rule', '@5', '--detail']
        translations:
          kind: node
          anchor: true
          description: Connections with destination NAT, including connections also using source NAT
          command: ['conntrack.nvyr.op', 'show', '@line']
          children:
            include_schema:
            - file: operational/conntrack-filters.yaml.i
              as: null
