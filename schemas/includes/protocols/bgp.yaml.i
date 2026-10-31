bgp:
  kind: node
  description: IPv4 and IPv6 unicast BGP
  anchor: true
  children:

    local-as:
      kind: leaf_node
      description: Local autonomous system number
      validators:
        integer-range:
          minimum: 1
          maximum: 4294967295
      hints:
        1-4294967295: Local autonomous system number

    description:
      kind: leaf_node
      description: BGP instance description (configuration metadata)
      hints:
        text: BGP instance description (configuration metadata); quote spaces
      validators:
        text: {}

    peer-group:
      kind: tag_node
      anchor: true
      description: Reusable settings within this BGP instance
      validators:
        regex:
          pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
      hints:
        name: Peer-group name
      children:

        include_schema:
        - file: protocols/bgp/peer-options.yaml.i
          as: null

    neighbor:
      kind: tag_node
      anchor: true
      description: BGP neighbor address or unnumbered interface
      validators:
        bgp-neighbor: {}
      hints:
        address: Unicast IPv4 or IPv6 peer address
        interface: Interface for an unnumbered peer
      children:

        include_schema:
        - file: protocols/bgp/peer-options.yaml.i
          as: null

        peer-group:
          kind: leaf_node
          description: Peer-group in this BGP instance
          validators:
            regex:
              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
          hints:
            name: Peer-group in this BGP instance

        interface:
          kind: leaf_node
          description: Interface used to reach an addressed peer
          validators:
            regex:
              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
          hints:
            interface: Peer-facing interface
          depends: interface
          suggestors:
            interfaces: {}

        ipv6-only:
          kind: leaf_node
          description: Use only IPv6 transport for an interface neighbor
          valueless: true
      depends: interface
      suggestors:
        interfaces: {}

    address-family:
      kind: node
      description: Unicast advertisements
      anchor: true
      children:

        include_schema:
        - file: protocols/bgp/ipv4.yaml.i
        - file: protocols/bgp/ipv6.yaml.i
    include_schema:
    - file: protocols/bgp/parameters.yaml.i
  script:
    name: bgp
    priority: 45
    register:
      vrf: default
