vpn:
  kind: node
  description: Exchange routes between this unicast table and the global VPN table
  anchor: true
  children:

    import:
      kind: leaf_node
      description: Import matching VPN routes into this routing table
      valueless: true

    export:
      kind: leaf_node
      description: Export routes from this routing table into VPN
      valueless: true

    route-distinguisher:
      kind: leaf_node
      description: Route distinguisher attached to exported routes
      hints:
        rd: ASN:number or IPv4:number
      validators:
        bgp-rd-rt: {}

    route-target:
      kind: node
      description: Route targets for VPN import and export
      anchor: true
      children:

        import:
          kind: leaf_node
          description: Route target for import
          hints:
            rt: ASN:number or IPv4:number
          validators:
            bgp-rd-rt: {}
          multi: true

        export:
          kind: leaf_node
          description: Route target for export
          hints:
            rt: ASN:number or IPv4:number
          validators:
            bgp-rd-rt: {}
          multi: true

        both:
          kind: leaf_node
          description: Route target for both
          hints:
            rt: ASN:number or IPv4:number
          validators:
            bgp-rd-rt: {}
          multi: true

    route-map:
      kind: node
      description: VPN import and export policy
      anchor: true
      children:

        import:
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

        export:
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

    label:
      kind: leaf_node
      description: 'Export label: automatic allocation or an explicit unreserved label'
      hints:
        16-1048574: Explicit unreserved MPLS label
      choices:
        auto: Allocate the export label automatically
      validators:
        mode: OR
        list:
          values: auto
        integer-range:
          minimum: 16
          maximum: 1048574

    allocation-mode:
      kind: leaf_node
      description: Export label allocation strategy
      choices:
        per-vrf: Share an export label within the VRF
        per-nexthop: Allocate an export label for each next hop
      validators:
        list:
          values: per-vrf per-nexthop

    next-hop:
      kind: leaf_node
      description: Override the next hop attached to exported VPN routes
      hints:
        address: Unicast IPv4 or IPv6 next-hop address
      validators:
        unicast-address: {}
