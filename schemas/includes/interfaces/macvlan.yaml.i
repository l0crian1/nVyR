macvlan:
  kind: tag_node
  dependency: interface
  anchor: true
  description: MAC-based virtual Ethernet interface
  validators:
    regex: {pattern: 'macvlan[0-9]{1,8}'}
  suggestors:
    interfaces: {prefix: macvlan}
  hints:
    macvlanN: MACVLAN interface name
  script:
    name: bridge
    priority: 12
  include_schema:
  - file: interfaces/common.yaml.i
    remove:
    - /mtu/default
    replace:
      /address:
        include_schema:
        - file: interfaces/address_dhcp.yaml.i
          as: null
    add:

      /source-interface:
        kind: leaf_node
        description: Parent Ethernet interface or VLAN interface
        depends: interface
        validators:
          regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
        suggestors:
          interfaces: {}
        hints:
          interface: Parent interface

      /mode:
        kind: leaf_node
        description: Delivery between MACVLAN interfaces on the same parent
        choices:
          vepa: Send traffic between siblings through an external switch
          private: Isolate siblings even when the external switch reflects traffic
        validators:
          list: {values: 'vepa private'}
        default:
          mode: direct
          value: vepa

      /dhcp-options:
        include_schema:
        - file: interfaces/dhcp-options.yaml.i
          as: null

      /dhcpv6-options:
        include_schema:
        - file: interfaces/dhcpv6-options.yaml.i
          as: null

      /dhcpv6-pd:
        include_schema:
        - file: interfaces/dhcpv6-pd.yaml.i
          as: null
