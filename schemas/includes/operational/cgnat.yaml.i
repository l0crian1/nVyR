cgnat:
  kind: node
  description: Deterministic carrier-grade NAT pools and subscriber allocations
  command: ['cgnat.nvyr.op', 'pools']
  children:

    pool:
      kind: tag_node
      description: Show a configured public address pool
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: CGN pool name
      suggestors:
        config-path: {path: 'nat cgnat pool'}
      command: ['cgnat.nvyr.op', 'pools', '--name', '@5']

    rule:
      kind: tag_node
      description: Show a CGN policy and its first-packet NAT counters
      validators:
        integer-range: {minimum: 1, maximum: 999999}
      hints:
        number: CGN policy number
      suggestors:
        config-path: {path: 'nat cgnat rule'}
      command: ['cgnat.nvyr.op', 'rules', '--number', '@5']

    rules:
      kind: node
      description: Show all CGN policies and first-packet NAT counters
      command: ['cgnat.nvyr.op', 'rules']

    subscriber:
      kind: tag_node
      description: Look up the configured public address and block for a subscriber
      validators:
        ipv4-address: {}
      hints:
        x.x.x.x: Subscriber IPv4 address
      command: ['cgnat.nvyr.op', 'allocation', '--subscriber', '@5']
      children:

        vrf:
          kind: tag_node
          description: Restrict lookup to a routing instance
          validators:
            regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
          hints:
            name: VRF name or default
          suggestors:
            config-path: {path: 'vrf name'}
          command: ['cgnat.nvyr.op', 'allocation', '--subscriber', '@5', '--vrf', '@7']

    public-address:
      kind: tag_node
      description: Reverse lookup a public IPv4 address and translated port or ICMP identifier
      validators:
        ipv4-address: {}
      hints:
        x.x.x.x: Public IPv4 address
      children:

        port:
          kind: tag_node
          description: Translated port or ICMP identifier to look up
          validators:
            integer-range: {minimum: 1, maximum: 65535}
          hints:
            1-65535: Translated port or echo identifier
          command: ['cgnat.nvyr.op', 'allocation', '--public', '@5', '--port', '@7']
