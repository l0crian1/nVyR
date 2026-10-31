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
