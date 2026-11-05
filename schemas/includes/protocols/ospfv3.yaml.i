ospfv3:
  kind: node
  description: OSPFv3 IPv6 routing
  anchor: true
  children:

    include_schema:
    - file: protocols/ospfv3/settings.yaml.i
      as: null
  script:
    name: ospfv3
    priority: 47
    register:
      vrf: default
    watch-before:
    - interfaces
    - policy
