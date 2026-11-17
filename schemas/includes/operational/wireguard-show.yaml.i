wireguard:
  kind: node
  description: WireGuard peers, endpoints, handshakes and transfer counters
  command: ['wireguard.nvyr.op', 'show']
  children:

    interface:
      kind: tag_node
      positional: true
      description: WireGuard interface
      validators:
        regex: {pattern: 'wg[0-9]+'}
      suggestors:
        interfaces: {prefix: wg}
      hints:
        wgN: WireGuard interface name
      command: ['wireguard.nvyr.op', 'show', '--interface', '@3']
      children:

        detail:
          kind: leaf_node
          valueless: true
          description: Public keys, allowed prefixes and keepalive settings
          command: ['wireguard.nvyr.op', 'show', '--interface', '@3', '--detail']

        peer:
          kind: tag_node
          description: Named peer
          validators:
            regex: {pattern: '[A-Za-z0-9][A-Za-z0-9_-]{0,62}'}
          suggestors:
            wireguard-peers: {}
          hints:
            name: Configured peer name
          command: ['wireguard.nvyr.op', 'show', '--interface', '@3', '--peer', '@5']
          children:

            detail:
              kind: leaf_node
              valueless: true
              description: Peer public key, allowed prefixes and keepalive settings
              command: ['wireguard.nvyr.op', 'show', '--interface', '@3', '--peer', '@5', '--detail']
