children:

  include_schema:
  - file: "operational/bgp-clear-target.yaml.i"
    as: null

  ipv4:
    kind: "node"
    description: "Reset IPv4 peers"
    children:

      include_schema:
      - file: "operational/bgp-clear-target.yaml.i"
        as: null

      unicast:
        kind: "node"
        description: "Reset unicast peers"
        children:

          include_schema:
          - file: "operational/bgp-clear-target.yaml.i"
            as: null

  ipv6:
    kind: "node"
    description: "Reset IPv6 peers"
    children:

      include_schema:
      - file: "operational/bgp-clear-target.yaml.i"
        as: null

      unicast:
        kind: "node"
        description: "Reset unicast peers"
        children:

          include_schema:
          - file: "operational/bgp-clear-target.yaml.i"
            as: null
