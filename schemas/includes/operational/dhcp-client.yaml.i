children:

  release:
    kind: node
    access: net-admin
    description: Release runtime resources
    children:

      dhcp:
        kind: node
        description: Release a DHCPv4 client lease
        children:

          interface:
            kind: leaf_node
            description: Interface whose DHCPv4 lease should be released
            command: ['dhcp.nvyr.op', 'release', '@4']
            validators:
              regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
            hints:
              interface: DHCPv4 client interface
            suggestors:
              interfaces: {}

      dhcpv6:
        kind: node
        description: Release a DHCPv6 client lease
        children:

          interface:
            kind: leaf_node
            description: Interface whose DHCPv6 lease should be released
            command: ['dhcp6.nvyr.op', 'release', '@4']
            validators:
              regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
            hints:
              interface: DHCPv6 client interface
            suggestors:
              interfaces: {}

  renew:
    kind: node
    access: net-admin
    description: Renew runtime resources
    children:

      dhcp:
        kind: node
        description: Renew or acquire a DHCPv4 client lease
        children:

          interface:
            kind: leaf_node
            description: Interface whose DHCPv4 lease should be renewed
            command: ['dhcp.nvyr.op', 'renew', '@4']
            validators:
              regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
            hints:
              interface: DHCPv4 client interface
            suggestors:
              interfaces: {}

      dhcpv6:
        kind: node
        description: Renew or acquire a DHCPv6 client lease
        children:

          interface:
            kind: leaf_node
            description: Interface whose DHCPv6 lease should be renewed
            command: ['dhcp6.nvyr.op', 'renew', '@4']
            validators:
              regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
            hints:
              interface: DHCPv6 client interface
            suggestors:
              interfaces: {}
