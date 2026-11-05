lldp:
  kind: node
  description: Watch LLDP neighbor additions, changes and removals
  command: ['lldp.nvyr.op', 'monitor']
  stream: true
  children:

    interface:
      kind: leaf_node
      description: Watch neighbors on this local interface
      validators:
        regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.:-]{0,14}'}
      suggestors:
        interfaces: {}
      hints:
        interface: Local interface name
      command: ['lldp.nvyr.op', 'monitor', '--interface', '@4']
      stream: true
