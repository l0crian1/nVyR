children: # address next hop (shared)

  include_schema:
  - file: protocols/static/forwarding-options.yaml.i
    as: null

  interface:
    kind: leaf_node
    description: Outgoing interface for this next hop
    depends: interface
    validators:
      static-interface: {}
    hints:
      name: Outgoing interface name
    suggestors:
      interfaces: {}

  onlink:
    kind: leaf_node
    description: Treat the next hop as directly attached to its specified interface
    valueless: true
