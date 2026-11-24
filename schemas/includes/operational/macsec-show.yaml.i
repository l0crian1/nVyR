macsec:
  kind: node
  description: MACsec secure channel and key agreement status
  command: ['macsec.nvyr.op','show']
  children:

    interface:
      kind: tag_node
      positional: true
      description: MACsec interface
      validators:
        regex: {pattern: 'macsec[0-9]{1,9}'}
      suggestors:
        interfaces: {prefix: macsec}
      hints:
        macsecN: MACsec interface name
      command: ['macsec.nvyr.op','show','--interface','@3']
      children:

        detail:
          kind: node
          description: Secure channel, key server and protection settings
          command: ['macsec.nvyr.op','show','--interface','@3','--detail']

        counters:
          kind: node
          description: Secure channel packet and byte counters
          command: ['macsec.nvyr.op','show','--interface','@3','--counters']
