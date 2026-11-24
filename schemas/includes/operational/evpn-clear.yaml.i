evpn:
  kind: node
  description: Reset EVPN duplicate address detection
  access: net-admin
  children:

    dup-addr:
      kind: node
      description: Clear duplicate address state
      children:

        vni:
          kind: tag_node
          description: VXLAN network identifier
          validators:
            integer-range: {minimum: 1, maximum: 16777215}
          hints:
            1-16777215: VXLAN network identifier
          command: ['bgp.nvyr.op', 'clear', '@line']
          children:

            mac:
              kind: tag_node
              description: Host MAC address
              validators:
                mac: {unicast: false}
              hints:
                mac: Ethernet address
              command: ['bgp.nvyr.op', 'clear', '@line']

            ip:
              kind: tag_node
              description: Host IP address
              validators:
                inet-address: {}
              hints:
                address: IPv4 or IPv6 address
              command: ['bgp.nvyr.op', 'clear', '@line']
