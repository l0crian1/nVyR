children:

  include_schema:
  - file: "operational/bgp-summary-end.yaml.i"
    as: null

  neighbor:
    kind: "tag_node"
    description: "Show one peer"
    validators:
      mode: "OR"
      inet-address: {}
      regex:
        pattern: "[A-Za-z][A-Za-z0-9_.-]{0,14}"
    hints:
      address: "Neighbor address or interface"
    command: ["bgp.nvyr.op","show","@line"]
    suggestors:
      bgp-peers: {}
    children:

      include_schema:
      - file: "operational/bgp-summary-end.yaml.i"
        as: null

  remote-as:
    kind: "tag_node"
    description: "Filter by remote autonomous system"
    validators:
      mode: "OR"
      integer-range:
        minimum: 1
        maximum: 4294967295
      list:
        values: "internal external"
    hints:
      ASN: "Remote AS number"
    command: ["bgp.nvyr.op","show","@line"]
    choices:
      internal: "Internal BGP peers"
      external: "External BGP peers"
    children:

      include_schema:
      - file: "operational/bgp-summary-end.yaml.i"
        as: null
