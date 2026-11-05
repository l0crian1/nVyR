lldp:
  kind: node
  description: Link Layer Discovery Protocol
  children:

    neighbors:
      kind: node
      description: Discovered LLDP neighbors
      command: ['lldp.nvyr.op', 'show', 'neighbors']
      children:

        detail:
          kind: node
          description: All advertised neighbor information
          command: ['lldp.nvyr.op', 'show', 'neighbors', '--detail']

        interface:
          kind: tag_node
          description: Neighbors on this local interface
          validators:
            regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.:-]{0,14}'}
          suggestors:
            interfaces: {}
          hints:
            interface: Local interface name
          command: ['lldp.nvyr.op', 'show', 'neighbors', '--interface', '@5']
          children:

            detail:
              kind: node
              description: All advertised neighbor information
              command: ['lldp.nvyr.op', 'show', 'neighbors', '--interface', '@5', '--detail']

    interfaces:
      kind: tag_node
      optional_value: true
      description: Local LLDP port settings
      validators:
        regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.:-]{0,14}'}
      suggestors:
        interfaces: {}
      hints:
        interface: Local interface name
      command: ['lldp.nvyr.op', 'show', 'interfaces', '--interface', '@4']
      children:

        detail:
          kind: node
          description: Detailed settings for all local LLDP ports
          command: ['lldp.nvyr.op', 'show', 'interfaces', '--interface', '@4', '--detail']

    statistics:
      kind: node
      description: LLDP packet and neighbor counters
      command: ['lldp.nvyr.op', 'show', 'statistics']
      children:

        interface:
          kind: leaf_node
          description: Counters for this local interface
          validators:
            regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.:-]{0,14}'}
          suggestors:
            interfaces: {}
          hints:
            interface: Local interface name
          command: ['lldp.nvyr.op', 'show', 'statistics', '--interface', '@5']

    local:
      kind: node
      description: Local chassis identity and management addresses
      command: ['lldp.nvyr.op', 'show', 'local']
