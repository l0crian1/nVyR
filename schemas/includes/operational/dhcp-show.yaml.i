children:

  dhcp-server:
    kind: node
    description: DHCPv4 leases, pools and listeners
    children:

      leases:
        kind: node
        description: Current leases and their remaining lifetimes
        command: ['dhcp_server.nvyr.op', 'show', '4', 'leases']

      pools:
        kind: node
        description: Allocation range usage by pool and subnet
        command: ['dhcp_server.nvyr.op', 'show', '4', 'pools']

      listeners:
        kind: node
        description: Server listener readiness
        command: ['dhcp_server.nvyr.op', 'show', '4', 'listeners']

      shared-network:
        kind: tag_node
        description: Filter by configured pool (shared network)
        validators:
          regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'}
        hints:
          name: Pool name
        suggestors:
          dhcp-pools: {family: 4}
        children:

          leases:
            kind: node
            description: Current leases and their remaining lifetimes
            command: ['dhcp_server.nvyr.op', 'show', '4', 'leases', '--shared-network', '@4']

          pools:
            kind: node
            description: Allocation range usage by pool and subnet
            command: ['dhcp_server.nvyr.op', 'show', '4', 'pools', '--shared-network', '@4']

          listeners:
            kind: node
            description: Server listener readiness
            command: ['dhcp_server.nvyr.op', 'show', '4', 'listeners', '--shared-network', '@4']

      vrf:
        kind: tag_node
        description: Filter by routing instance
        validators:
          regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
        choices:
          default: Default routing instance
        suggestors:
          config-path: {path: 'vrf name'}
        hints:
          name: Routing instance name
        children:

          leases:
            kind: node
            description: Current leases and their remaining lifetimes
            command: ['dhcp_server.nvyr.op', 'show', '4', 'leases', '--vrf', '@4']

          pools:
            kind: node
            description: Allocation range usage by pool and subnet
            command: ['dhcp_server.nvyr.op', 'show', '4', 'pools', '--vrf', '@4']

          listeners:
            kind: node
            description: Server listener readiness
            command: ['dhcp_server.nvyr.op', 'show', '4', 'listeners', '--vrf', '@4']

          shared-network:
            kind: tag_node
            description: Filter by configured pool (shared network)
            validators:
              regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'}
            hints:
              name: Pool name
            suggestors:
              dhcp-pools: {family: 4}
            children:

              leases:
                kind: node
                description: Current leases and their remaining lifetimes
                command: ['dhcp_server.nvyr.op', 'show', '4', 'leases', '--vrf', '@4', '--shared-network', '@6']

              pools:
                kind: node
                description: Allocation range usage by pool and subnet
                command: ['dhcp_server.nvyr.op', 'show', '4', 'pools', '--vrf', '@4', '--shared-network', '@6']

              listeners:
                kind: node
                description: Server listener readiness
                command: ['dhcp_server.nvyr.op', 'show', '4', 'listeners', '--vrf', '@4', '--shared-network', '@6']

  dhcpv6-server:
    kind: node
    description: DHCPv6 leases, pools and listeners
    children:

      leases:
        kind: node
        description: Current leases and their remaining lifetimes
        command: ['dhcp_server.nvyr.op', 'show', '6', 'leases']

      pools:
        kind: node
        description: Allocation range usage by pool and subnet
        command: ['dhcp_server.nvyr.op', 'show', '6', 'pools']

      listeners:
        kind: node
        description: Server listener readiness
        command: ['dhcp_server.nvyr.op', 'show', '6', 'listeners']

      shared-network:
        kind: tag_node
        description: Filter by configured pool (shared network)
        validators:
          regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'}
        hints:
          name: Pool name
        suggestors:
          dhcp-pools: {family: 6}
        children:

          leases:
            kind: node
            description: Current leases and their remaining lifetimes
            command: ['dhcp_server.nvyr.op', 'show', '6', 'leases', '--shared-network', '@4']

          pools:
            kind: node
            description: Allocation range usage by pool and subnet
            command: ['dhcp_server.nvyr.op', 'show', '6', 'pools', '--shared-network', '@4']

          listeners:
            kind: node
            description: Server listener readiness
            command: ['dhcp_server.nvyr.op', 'show', '6', 'listeners', '--shared-network', '@4']

      vrf:
        kind: tag_node
        description: Filter by routing instance
        validators:
          regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
        choices:
          default: Default routing instance
        suggestors:
          config-path: {path: 'vrf name'}
        hints:
          name: Routing instance name
        children:

          leases:
            kind: node
            description: Current leases and their remaining lifetimes
            command: ['dhcp_server.nvyr.op', 'show', '6', 'leases', '--vrf', '@4']

          pools:
            kind: node
            description: Allocation range usage by pool and subnet
            command: ['dhcp_server.nvyr.op', 'show', '6', 'pools', '--vrf', '@4']

          listeners:
            kind: node
            description: Server listener readiness
            command: ['dhcp_server.nvyr.op', 'show', '6', 'listeners', '--vrf', '@4']

          shared-network:
            kind: tag_node
            description: Filter by configured pool (shared network)
            validators:
              regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'}
            hints:
              name: Pool name
            suggestors:
              dhcp-pools: {family: 6}
            children:

              leases:
                kind: node
                description: Current leases and their remaining lifetimes
                command: ['dhcp_server.nvyr.op', 'show', '6', 'leases', '--vrf', '@4', '--shared-network', '@6']

              pools:
                kind: node
                description: Allocation range usage by pool and subnet
                command: ['dhcp_server.nvyr.op', 'show', '6', 'pools', '--vrf', '@4', '--shared-network', '@6']

              listeners:
                kind: node
                description: Server listener readiness
                command: ['dhcp_server.nvyr.op', 'show', '6', 'listeners', '--vrf', '@4', '--shared-network', '@6']

  dhcp-client:
    kind: node
    description: DHCPv4 client leases and runtime state
    command: ['dhcp.nvyr.op', 'show']
    children:

      detail:
        kind: node
        description: Received lease information and local installation state
        command: ['dhcp.nvyr.op', 'show', '--detail']

      interface:
        kind: tag_node
        description: Inspect a DHCPv4 client interface
        validators:
          regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
        suggestors:
          interfaces: {}
        hints:
          interface: DHCPv4 client interface
        command: ['dhcp.nvyr.op', 'show', '--interface', '@4']
        children:

          detail:
            kind: node
            description: Received lease information and local installation state
            command: ['dhcp.nvyr.op', 'show', '--interface', '@4', '--detail']
