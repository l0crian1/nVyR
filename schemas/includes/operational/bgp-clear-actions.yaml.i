children:

  soft:
    kind: "node"
    description: "Soft refresh without resetting the session"
    command: ["bgp.nvyr.op","clear","@line"]
    children:

      in:
        kind: "node"
        description: "Reprocess incoming routes"
        command: ["bgp.nvyr.op","clear","@line"]

      out:
        kind: "node"
        description: "Readvertise outgoing routes"
        command: ["bgp.nvyr.op","clear","@line"]

  in:
    kind: "node"
    description: "Refresh incoming routes"
    command: ["bgp.nvyr.op","clear","@line"]
    children:

      prefix-filter:
        kind: "node"
        description: "Refresh the outbound route filter"
        command: ["bgp.nvyr.op","clear","@line"]

  out:
    kind: "node"
    description: "Readvertise outgoing routes"
    command: ["bgp.nvyr.op","clear","@line"]

  message-stats:
    kind: "node"
    description: "Reset peer message statistics"
    command: ["bgp.nvyr.op","clear","@line"]

  capabilities:
    kind: "node"
    description: "Resend supported dynamic capabilities"
    command: ["bgp.nvyr.op","clear","@line"]
