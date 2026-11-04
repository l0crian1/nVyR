nat:
  kind: node
  description: Source and destination NAT packet logs
  command: ['logs.nvyr.op', 'show', '@3']
  stream: true
  children:

    follow:
      kind: node
      description: Follow new NAT packet logs
      command: ['logs.nvyr.op', 'show', '@3', '--follow']
      stream: true

    source:
      kind: node
      description: Source NAT packet logs
      command: ['logs.nvyr.op', 'show', '@3', '--direction', 'source']
      stream: true
      children:

        follow:
          kind: node
          description: Follow new packet logs
          command: ['logs.nvyr.op', 'show', '@3', '--direction', 'source', '--follow']
          stream: true

        rule:
          kind: tag_node
          description: Logs from one exact NAT rule
          hints:
            1-999999: NAT rule number
          validators:
            integer-range: {minimum: 1, maximum: 999999}
          command: ['logs.nvyr.op', 'show', '@3', '--direction', 'source', '--rule', '@6']
          stream: true
          children:

            follow:
              kind: node
              description: Follow new packet logs
              command: ['logs.nvyr.op', 'show', '@3', '--direction', 'source', '--rule', '@6', '--follow']
              stream: true

    destination:
      kind: node
      description: Destination NAT packet logs
      command: ['logs.nvyr.op', 'show', '@3', '--direction', 'destination']
      stream: true
      children:

        follow:
          kind: node
          description: Follow new packet logs
          command: ['logs.nvyr.op', 'show', '@3', '--direction', 'destination', '--follow']
          stream: true

        rule:
          kind: tag_node
          description: Logs from one exact NAT rule
          hints:
            1-999999: NAT rule number
          validators:
            integer-range: {minimum: 1, maximum: 999999}
          command: ['logs.nvyr.op', 'show', '@3', '--direction', 'destination', '--rule', '@6']
          stream: true
          children:

            follow:
              kind: node
              description: Follow new packet logs
              command: ['logs.nvyr.op', 'show', '@3', '--direction', 'destination', '--rule', '@6', '--follow']
              stream: true
