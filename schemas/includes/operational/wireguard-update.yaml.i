wireguard:
  kind: tag_node
  access: net-admin
  description: Resolve configured hostname endpoints now
  validators:
    regex: {pattern: 'wg[0-9]+'}
  suggestors:
    config-path: {path: interfaces wireguard}
  hints:
    wgN: WireGuard interface name
  command: ['wireguard.nvyr.op', 'refresh', '@3']
  unattended: true
  children:

    peer:
      kind: tag_node
      description: Refresh one peer endpoint
      validators:
        regex: {pattern: '[A-Za-z0-9][A-Za-z0-9_-]{0,62}'}
      suggestors:
        wireguard-peers: {}
      hints:
        name: Configured peer name
      children:

        endpoint:
          kind: node
          description: Resolve the hostname even when a recent handshake exists
          command: ['wireguard.nvyr.op', 'refresh', '@3', '--peer', '@5']
          unattended: true
