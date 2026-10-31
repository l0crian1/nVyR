children:

  routes:
    kind: "node"
    description: "Accepted routes received from this peer"
    command: ["bgp.nvyr.op","show","@line"]

  advertised-routes:
    kind: "node"
    description: "Routes advertised to this peer"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      detail:
        kind: "node"
        description: "Show detailed route attributes"
        command: ["bgp.nvyr.op","show","@line"]

  received-routes:
    kind: "node"
    description: "Unfiltered received routes; requires inbound soft reconfiguration"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      detail:
        kind: "node"
        description: "Show detailed route attributes"
        command: ["bgp.nvyr.op","show","@line"]

  filtered-routes:
    kind: "node"
    description: "Routes rejected by inbound policy"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      detail:
        kind: "node"
        description: "Show detailed route attributes"
        command: ["bgp.nvyr.op","show","@line"]

  bestpath-routes:
    kind: "node"
    description: "Best paths received from this peer"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      detail:
        kind: "node"
        description: "Show detailed route attributes"
        command: ["bgp.nvyr.op","show","@line"]

  prefix-counts:
    kind: "node"
    description: "Received prefix counts"
    command: ["bgp.nvyr.op","show","@line"]

  flap-statistics:
    kind: "node"
    description: "Route flap statistics"
    command: ["bgp.nvyr.op","show","@line"]

  dampened-routes:
    kind: "node"
    description: "Dampened routes received from this peer"
    command: ["bgp.nvyr.op","show","@line"]
