ipv6-vpn:
  kind: node
  description: IPv6 VPN routing table
  anchor: true
  children:

    disable-retain-route-target-all:
      kind: leaf_node
      description: Discard VPN routes not imported by a local VRF
      valueless: true

    network:
      kind: tag_node
      description: Originate a VPN prefix with an explicit RD and label
      anchor: true
      children:

        route-distinguisher:
          kind: tag_node
          description: An RD distinguishes this VPN network from the same prefix in other VPNs
          anchor: true
          children:

            label:
              kind: leaf_node
              description: Explicit VPN label
              hints:
                16-1048574: MPLS label advertised with this VPN prefix
              validators:
                integer-range:
                  minimum: 16
                  maximum: 1048574

            route-map:
              kind: leaf_node
              description: Route-map applied at the VRF/VPN boundary
              validators:
                regex:
                  pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
              hints:
                name: Configured route-map
              depends: policy-route-map
              suggestors:
                config-path:
                  path: policy route-map
          validators:
            bgp-rd-rt: {}
          hints:
            rd: ASN:number or IPv4:number
      validators:
        network:
          version: 6
      hints:
        prefix: IPv6 network
