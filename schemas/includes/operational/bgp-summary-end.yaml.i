children:

  terse:
    kind: "node"
    description: "Hide instance totals"
    command: ["bgp.nvyr.op","show","@line"]
    children:

      wide:
        kind: "node"
        description: "Display wide summary columns"
        command: ["bgp.nvyr.op","show","@line"]

  wide:
    kind: "node"
    description: "Display wide summary columns"
    command: ["bgp.nvyr.op","show","@line"]
