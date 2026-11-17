bgp:
  kind: "node"

  description: "BGP routing state"

  command: ["bgp.nvyr.op","show","@line"]

  children:

    include_schema:
    - file: "operational/bgp-context.yaml.i"
      as: null
      add:
        /community-list/optional_value: true
        /community-list/suggestors:
          policy-community-lists: {}
        /community-list/children/detail:
          kind: node
          description: Show the community-list definition, rather than matching routes
          command: ['bgp.nvyr.op', 'show', '@line']
        /large-community-list/optional_value: true
        /large-community-list/suggestors:
          policy-community-lists: {large: true}
        /large-community-list/children/detail:
          kind: node
          description: Show the large-community-list definition, rather than matching routes
          command: ['bgp.nvyr.op', 'show', '@line']
    - file: operational/policy-as-path.yaml.i

    extcommunity-list:
      kind: node
      description: Extended-community list definitions
      command: ["bgp.nvyr.op", "show", "@line"]
      children:

        name:
          kind: tag_node
          description: Extended-community list name
          positional: true
          validators:
            regex:
              pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
          hints:
            name: Extended-community list name
          suggestors:
            policy-community-lists: {extended: true}
          children:

            detail:
              kind: node
              description: Extended-community list definition
              command: ["bgp.nvyr.op", "show", "@line"]

    mplsvpn-nh-label-bind:
      kind: node
      description: VPN next-hop label bindings
      command: ["bgp.nvyr.op", "show", "@line"]
      children:

        detail:
          kind: node
          description: Detailed VPN next-hop label bindings
          command: ["bgp.nvyr.op", "show", "@line"]

    labelpool:
      kind: node
      description: BGP label allocation
      children:

        summary:
          kind: node
          description: Label-pool summary
          command: ["bgp.nvyr.op", "show", "@line"]

        inuse:
          kind: node
          description: Labels currently in use
          command: ["bgp.nvyr.op", "show", "@line"]

        ledger:
          kind: node
          description: Label allocation ledger
          command: ["bgp.nvyr.op", "show", "@line"]

        requests:
          kind: node
          description: Pending label requests
          command: ["bgp.nvyr.op", "show", "@line"]

        chunks:
          kind: node
          description: Label chunks assigned by Zebra
          command: ["bgp.nvyr.op", "show", "@line"]

    vrf:
      kind: "tag_node"
      description: "BGP state in a routing instance"
      validators:
        regex:
          pattern: "[a-zA-Z][a-zA-Z0-9_.-]{0,14}"
      hints:
        name: "VRF name"
      command: ["bgp.nvyr.op","show","@line"]
      choices:
        default: "Default routing instance"
        all: "All routing instances"
      suggestors:
        config-path:
          path: "vrf name"
      children:

        include_schema:
        - file: "operational/bgp-context.yaml.i"
          as: null

    router:
      kind: "node"
      description: "BGP router and graceful restart information"
      command: ["bgp.nvyr.op","show","@line"]

    vrfs:
      kind: "node"
      description: "BGP routing instance summary"
      command: ["bgp.nvyr.op","show","@line"]
      children:

        name:
          kind: "tag_node"
          description: "Show one routing instance"
          validators:
            regex:
              pattern: "[a-zA-Z][a-zA-Z0-9_.-]{0,14}"
          hints:
            name: "VRF name"
          command: ["bgp.nvyr.op","show","@line"]
          positional: true
          suggestors:
            config-path:
              path: "vrf name"
