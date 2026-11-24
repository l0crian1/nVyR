l2vpn-evpn:
  kind: node
  description: Tenant EVPN prefix advertisements and import/export targets
  anchor: true
  children:

    include_schema:
    - file: protocols/bgp/evpn-targets.yaml.i
      as: null

    advertise:
      kind: node
      description: Advertise tenant unicast routes as EVPN IP prefixes
      anchor: true
      children:

        ipv4-unicast:
          kind: node
          description: Advertise ipv4 unicast prefixes
          anchor: true
          children:

            gateway-ip:
              kind: leaf_node
              description: Use the gateway IP overlay index
              valueless: true

            route-map:
              kind: leaf_node
              description: Select tenant unicast routes for export
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'}
              hints:
                name: Configured route-map
              depends: policy-route-map
              suggestors:
                config-path: {path: policy route-map}

        ipv6-unicast:
          kind: node
          description: Advertise ipv6 unicast prefixes
          anchor: true
          children:

            gateway-ip:
              kind: leaf_node
              description: Use the gateway IP overlay index
              valueless: true

            route-map:
              kind: leaf_node
              description: Select tenant unicast routes for export
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'}
              hints:
                name: Configured route-map
              depends: policy-route-map
              suggestors:
                config-path: {path: policy route-map}

    default-originate:
      kind: node
      description: Originate an EVPN default prefix
      anchor: true
      children:

        ipv4:
          kind: leaf_node
          description: Originate an IPv4 default
          valueless: true

        ipv6:
          kind: leaf_node
          description: Originate an IPv6 default
          valueless: true
