vif:
  kind: tag_node
  anchor: true
  dependency: interface
  dependency-format: '{parent}.{value}'
  description: 802.1Q VLAN subinterface
  validators:
    mode: AND
    integer-range: {minimum: 1, maximum: 4094}
    regex: {pattern: '[1-9][0-9]{0,3}'}
  hints:
    1-4094: VLAN ID; interface name is parent.VLAN
  include_schema:
  - file: interfaces/common.yaml.i
    add:
      /dhcp-options:
        include_schema:
        - file: interfaces/dhcp-options.yaml.i
          as: null
    remove:
    - /mtu/default
    replace:
      /mtu/description: Maximum transmission unit; inherits the parent when omitted
      /address:
        include_schema:
        - file: interfaces/address_dhcp.yaml.i
          as: null
