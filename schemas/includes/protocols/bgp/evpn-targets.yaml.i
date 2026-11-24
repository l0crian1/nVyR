children:

  route-distinguisher:
    kind: leaf_node
    description: EVPN route distinguisher
    validators:
      bgp-rd-rt: {}
    hints:
      rd: ASN:number or IPv4:number

  route-target:
    kind: node
    description: EVPN import and export route targets
    anchor: true
    children:

      both:
        kind: leaf_node
        description: Route target for both
        validators:
          bgp-rd-rt: {}
        hints:
          rt: ASN:number or IPv4:number
        multi: true

      import:
        kind: leaf_node
        description: Route target for import
        validators:
          bgp-rd-rt: {}
        hints:
          rt: ASN:number or IPv4:number
        multi: true

      export:
        kind: leaf_node
        description: Route target for export
        validators:
          bgp-rd-rt: {}
        hints:
          rt: ASN:number or IPv4:number
        multi: true
