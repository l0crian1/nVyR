children:

  target:
    kind: "tag_node"
    description: "Peer address, AS number, or all peers"
    validators:
      mode: "OR"
      inet-address: {}
      integer-range:
        minimum: 1
        maximum: 4294967295
      list:
        values: "* external"
    hints:
      address: "Peer address"
      ASN: "Remote AS number"
    command: ["bgp.nvyr.op","clear","@line"]
    positional: true
    choices:
      "*": "All peers"
      external: "All external peers"
    suggestors:
      bgp-peers: {}
    children:

      include_schema:
      - file: "operational/bgp-clear-actions.yaml.i"
        as: null

  peer-group:
    kind: "tag_node"
    description: "Reset members of a peer group"
    validators:
      regex:
        pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
    hints:
      name: "Peer group name"
    command: ["bgp.nvyr.op","clear","@line"]
    suggestors:
      bgp-peer-groups: {}
    children:

      include_schema:
      - file: "operational/bgp-clear-actions.yaml.i"
        as: null
