bgp:
  kind: "node"

  description: "Reset BGP sessions or refresh routes"

  children:

    include_schema:
    - file: "operational/bgp-clear-context.yaml.i"
      as: null

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
