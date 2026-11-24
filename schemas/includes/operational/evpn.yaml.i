evpn:
  kind: node
  description: Zebra Ethernet VPN forwarding state
  children:

    vni:
      kind: tag_node
      description: VXLAN network identifier
      validators:
        integer-range: {minimum: 1, maximum: 16777215}
      hints:
        1-16777215: VXLAN network identifier
      command: ['bgp.nvyr.op', 'show', '@line']
      optional_value: true

    mac:
      kind: node
      description: EVPN MAC forwarding entries
      children:

        vni:
          kind: tag_node
          description: VXLAN network identifier
          validators:
            integer-range: {minimum: 1, maximum: 16777215}
          hints:
            1-16777215: VXLAN network identifier
          command: ['bgp.nvyr.op', 'show', '@line']
          children:

            duplicate:
              kind: node
              description: Show entries marked duplicate
              command: ['bgp.nvyr.op', 'show', '@line']

    arp-cache:
      kind: node
      description: EVPN ARP and IPv6 neighbor entries
      children:

        vni:
          kind: tag_node
          description: VXLAN network identifier
          validators:
            integer-range: {minimum: 1, maximum: 16777215}
          hints:
            1-16777215: VXLAN network identifier
          command: ['bgp.nvyr.op', 'show', '@line']
          children:

            duplicate:
              kind: node
              description: Show entries marked duplicate
              command: ['bgp.nvyr.op', 'show', '@line']

    rmac:
      kind: node
      description: Remote router MAC addresses
      children:

        vni:
          kind: tag_node
          description: Layer 3 VNI
          validators:
            integer-range: {minimum: 1, maximum: 16777215}
          hints:
            1-16777215: VXLAN network identifier
          command: ['bgp.nvyr.op', 'show', '@line']

    next-hops:
      kind: node
      description: Remote EVPN next hops
      children:

        vni:
          kind: tag_node
          description: Layer 3 VNI
          validators:
            integer-range: {minimum: 1, maximum: 16777215}
          hints:
            1-16777215: VXLAN network identifier
          command: ['bgp.nvyr.op', 'show', '@line']
