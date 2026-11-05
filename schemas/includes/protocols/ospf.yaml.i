ospf:
  kind: node
  description: OSPFv2 IPv4 routing
  anchor: true
  children:

    include_schema:
    - file: protocols/ospf/settings.yaml.i
      as: null
  script:
    name: ospf
    priority: 46
    register:
      vrf: default
    watch-before:
    - interfaces
    - policy
