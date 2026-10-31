children:

  include_schema:
  - file: "operational/bgp-table.yaml.i"
    as: null
    add:
      "/neighbors/command": ["bgp.nvyr.op","show","@line"]
      "/neighbors/children/peer/command": ["bgp.nvyr.op","show","@line"]

      "/neighbors/children/peer/children/graceful-restart":
        kind: "node"
        description: "Graceful restart capabilities and state"
        command: ["bgp.nvyr.op","show","@line"]

  bestpath:
    kind: "node"
    description: "Configured best-path selection criteria"
    command: ["bgp.nvyr.op","show","@line"]

  peer-group:
    kind: "node"
    description: "Configured peer groups"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      name:
        kind: "tag_node"
        description: "Show one peer group"
        validators:
          regex:
            pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
        hints:
          name: "Peer group name"
        command: ["bgp.nvyr.op","show","@line"]
        positional: true
        suggestors:
          bgp-peer-groups: {}

  nexthop:
    kind: "node"
    description: "Next-hop tracking status"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      detail:
        kind: "node"
        description: "Detailed next-hop tracking"
        command: ["bgp.nvyr.op","show","@line"]

      address:
        kind: "tag_node"
        description: "Track one next hop"
        validators:
          inet-address: {}
        hints:
          address: "IPv4 or IPv6 next hop"
        command: ["bgp.nvyr.op","show","@line"]
        positional: true
        children:

          detail:
            kind: "node"
            description: "Detailed next-hop tracking"
            command: ["bgp.nvyr.op","show","@line"]

  import-check-table:
    kind: "node"
    description: "Network import-check state"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      detail:
        kind: "node"
        description: "Detailed import-check state"
        command: ["bgp.nvyr.op","show","@line"]

  ipv4:
    kind: "node"
    description: "IPv4 BGP unicast routing state"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      include_schema:
      - file: "operational/bgp-table.yaml.i"
        as: null
        add:
          "/neighbors/command": ["bgp.nvyr.op","show","@line"]
          "/neighbors/children/peer/command": ["bgp.nvyr.op","show","@line"]

          "/neighbors/children/peer/children/graceful-restart":
            kind: "node"
            description: "Graceful restart capabilities and state"
            command: ["bgp.nvyr.op","show","@line"]

      unicast:
        kind: "node"
        description: "Unicast BGP routing state"
        command: ["bgp.nvyr.op","show","@line"]
        children:

          include_schema:
          - file: "operational/bgp-table.yaml.i"
            as: null

  ipv6:
    kind: "node"
    description: "IPv6 BGP unicast routing state"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      include_schema:
      - file: "operational/bgp-table.yaml.i"
        as: null
        add:
          "/neighbors/command": ["bgp.nvyr.op","show","@line"]
          "/neighbors/children/peer/command": ["bgp.nvyr.op","show","@line"]

          "/neighbors/children/peer/children/graceful-restart":
            kind: "node"
            description: "Graceful restart capabilities and state"
            command: ["bgp.nvyr.op","show","@line"]

      unicast:
        kind: "node"
        description: "Unicast BGP routing state"
        command: ["bgp.nvyr.op","show","@line"]
        children:

          include_schema:
          - file: "operational/bgp-table.yaml.i"
            as: null
