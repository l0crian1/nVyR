ethernet:
  include_schema:
  - file: interfaces/common.yaml.i
    add:
      /dhcp-options:
        include_schema:
        - file: interfaces/dhcp-options.yaml.i
          as: null
      /vif:
        include_schema:
        - file: interfaces/vif.yaml.i
          as: null
    replace:
      /address:
        include_schema:
        - file: interfaces/address_dhcp.yaml.i
          as: null
  kind: tag_node
  dependency: interface
  anchor: true
  description: Ethernet interface configuration
  validators:
    regex: {pattern: 'eth[0-9]+'}
  suggestors:
    interfaces: {prefix: eth}
  script:
    name: ethernet
    priority: 10
  hints:
    ethN: Ethernet interface name
