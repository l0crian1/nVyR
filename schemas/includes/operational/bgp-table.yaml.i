children:

  summary:
    kind: "node"
    description: "BGP peer summary"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      include_schema:
      - file: "operational/bgp-summary-filters.yaml.i"
        as: null

      established:
        kind: "node"
        description: "Peers successfully exchanging routes"
        command: ["bgp.nvyr.op","show","@line"]
        children:

          include_schema:
          - file: "operational/bgp-summary-filters.yaml.i"
            as: null

      failed:
        kind: "node"
        description: "Peers not successfully exchanging routes"
        command: ["bgp.nvyr.op","show","@line"]
        children:

          include_schema:
          - file: "operational/bgp-summary-filters.yaml.i"
            as: null

  statistics:
    kind: "node"
    description: "BGP route statistics"
    command: ["bgp.nvyr.op","show","@line"]

  neighbors:
    kind: "node"
    description: "BGP neighbors and their routes"
    children:

      peer:
        kind: "tag_node"
        description: "Neighbor address or interface"
        validators:
          mode: "OR"
          inet-address: {}
          regex:
            pattern: "[A-Za-z][A-Za-z0-9_.-]{0,14}"
        hints:
          address: "Neighbor address or interface"
        positional: true
        suggestors:
          bgp-peers: {}
        children:

          include_schema:
          - file: "operational/bgp-neighbor-options.yaml.i"
            as: null

  destination:
    kind: "tag_node"
    description: "Look up an address or prefix"
    validators:
      mode: "OR"
      ipv4-address: {}
      ipv4-prefix: {}
      ipv6-address: {}
      ipv6-prefix: {}
    hints:
      address: "IPv4 or IPv6 address"
      prefix: "IPv4 or IPv6 prefix"
    command: ["bgp.nvyr.op","show","@line"]
    positional: true
    children:

      longer-prefixes:
        kind: "node"
        description: "Routes contained in this prefix"
        command: ["bgp.nvyr.op","show","@line"]

      bestpath:
        kind: "node"
        description: "Show only the selected best path"
        command: ["bgp.nvyr.op","show","@line"]

      multipath:
        kind: "node"
        description: "Show multipath candidates"
        command: ["bgp.nvyr.op","show","@line"]

      internal:
        kind: "node"
        description: "Include internal path details"
        command: ["bgp.nvyr.op","show","@line"]
        children:

          bestpath:
            kind: "node"
            description: "Show only the selected best path"
            command: ["bgp.nvyr.op","show","@line"]

          multipath:
            kind: "node"
            description: "Show multipath candidates"
            command: ["bgp.nvyr.op","show","@line"]

  self-originate:
    kind: "node"
    description: "Locally originated routes"
    command: ["bgp.nvyr.op","show","@line"]

  cidr-only:
    kind: "node"
    description: "Routes that do not use a natural classful mask"
    command: ["bgp.nvyr.op","show","@line"]

  version:
    kind: "tag_node"
    description: "Routes changed since this table version"
    validators:
      integer-range:
        minimum: 1
        maximum: 4294967295
    hints:
      number: "BGP table version"
    command: ["bgp.nvyr.op","show","@line"]

  dampening:
    kind: "node"
    description: "Route flap damping status"
    children:

      flap-statistics:
        kind: "node"
        description: "Route flap counts"
        command: ["bgp.nvyr.op","show","@line"]

      dampened-paths:
        kind: "node"
        description: "Currently dampened paths"
        command: ["bgp.nvyr.op","show","@line"]

      parameters:
        kind: "node"
        description: "Configured damping parameters"
        command: ["bgp.nvyr.op","show","@line"]

  route-map:
    kind: "tag_node"
    description: "Routes matching a route-map"
    validators:
      regex:
        pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
    hints:
      name: "Policy name"
    command: ["bgp.nvyr.op","show","@line"]
    suggestors:
      config-path:
        path: "policy route-map"

  prefix-list:
    kind: "tag_node"
    description: "Routes matching a prefix-list"
    validators:
      regex:
        pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
    hints:
      name: "Policy name"
    command: ["bgp.nvyr.op","show","@line"]

  access-list:
    kind: "tag_node"
    description: "Routes matching an access-list"
    validators:
      regex:
        pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
    hints:
      name: "Policy name"
    command: ["bgp.nvyr.op","show","@line"]

  filter-list:
    kind: "tag_node"
    description: "Routes matching an AS-path access list"
    validators:
      regex:
        pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
    hints:
      name: "Policy name"
    command: ["bgp.nvyr.op","show","@line"]
    suggestors:
      config-path:
        path: "policy as-path-list"

  community-list:
    kind: "tag_node"
    description: "Routes matching a community-list"
    validators:
      regex:
        pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
    hints:
      name: "Policy name"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      exact-match:
        kind: "node"
        description: "Require an exact community match"
        command: ["bgp.nvyr.op","show","@line"]

  large-community-list:
    kind: "tag_node"
    description: "Routes matching a large-community-list"
    validators:
      regex:
        pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
    hints:
      name: "Policy name"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      exact-match:
        kind: "node"
        description: "Require an exact community match"
        command: ["bgp.nvyr.op","show","@line"]

  community:
    kind: "node"
    description: "Routes with community attributes"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      value:
        kind: "tag_node"
        description: "Match one community"
        validators:
          bgp-community:
            large: false
            modifiers: false
        hints:
          value: "AS:value or well-known community"
        command: ["bgp.nvyr.op","show","@line"]
        positional: true
        children:

          exact-match:
            kind: "node"
            description: "Require an exact community match"
            command: ["bgp.nvyr.op","show","@line"]

  large-community:
    kind: "node"
    description: "Routes with large-community attributes"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      value:
        kind: "tag_node"
        description: "Match one large-community"
        validators:
          bgp-community:
            large: true
            modifiers: false
        hints:
          value: "AS:local-data:local-data"
        command: ["bgp.nvyr.op","show","@line"]
        positional: true
        children:

          exact-match:
            kind: "node"
            description: "Require an exact community match"
            command: ["bgp.nvyr.op","show","@line"]
