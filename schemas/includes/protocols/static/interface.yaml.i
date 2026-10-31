interface:
  kind: tag_node
  description: Interface-only next hop
  depends: interface
  validators:
    static-interface: {}
  hints:
    name: Outgoing interface name
  suggestors:
    interfaces: {}
  children: # interface

    include_schema:
    - file: protocols/static/forwarding-options.yaml.i
      as: null
