bgp:
  kind: "node"

  description: "Reset BGP sessions or refresh routes"

  children:

    include_schema:
    - file: "operational/bgp-clear-context.yaml.i"
      as: null

    l2vpn:
      kind: node
      description: Layer 2 VPN address families
      children:

        evpn:
          kind: node
          description: Refresh EVPN peers
          children:

            peer:
              kind: tag_node
              description: EVPN neighbor address
              positional: true
              validators:
                inet-address: {}
              hints:
                address: IPv4 or IPv6 address
              children:

                soft:
                  kind: node
                  description: Refresh EVPN routes without resetting the session
                  children:

                    in:
                      kind: node
                      description: Reprocess incoming routes
                      command: ['bgp.nvyr.op', 'clear', '@line']

                    out:
                      kind: node
                      description: Readvertise outgoing routes
                      command: ['bgp.nvyr.op', 'clear', '@line']

    vrf:
      kind: "tag_node"
      description: "Reset peers in a routing instance"
      validators:
        regex:
          pattern: "[a-zA-Z][a-zA-Z0-9_.-]{0,14}"
      hints:
        name: "VRF name"
      choices:
        default: "Default routing instance"
      suggestors:
        config-path:
          path: "vrf name"
      children:

        include_schema:
        - file: "operational/bgp-clear-context.yaml.i"
          as: null

  access: "net-admin"
