interfaces:
  kind: tag_node
  optional_value: true
  description: Interface information
  command: ['interfaces.nvyr.op', 'show', '--intf_name', '@3']
  suggestors:
    interfaces: {}
  validators:
    regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.:-]{0,14}'}
  hints:
    interface: Interface name (for example eth0)
  children: # interfaces

    include_schema:
    - file: operational/bridge.yaml.i
    - file: operational/bond.yaml.i
    - file: operational/vxlan.yaml.i
    - file: operational/interface_options.yaml.i
      as: null
      add:
        /detail/command: ['interfaces.nvyr.op', 'show', '--intf_name', '@3', '--detail']
        /statistics/command: ['interfaces.nvyr.op', 'show', '--intf_name', '@3', '--statistics']
        /offload/command: ['interfaces.nvyr.op', 'hardware', 'offload', '--intf_name', '@3']
        /queues/command: ['interfaces.nvyr.op', 'hardware', 'queues', '--intf_name', '@3']
        /hardware-statistics/command: ['interfaces.nvyr.op', 'hardware', 'hardware-statistics', '--intf_name', '@3']
        /transceiver/command: ['interfaces.nvyr.op', 'hardware', 'transceiver', '--intf_name', '@3']

    wireguard:
      kind: tag_node
      optional_value: true
      description: WireGuard interface addresses and kernel state
      command: ['interfaces.nvyr.op', 'show', '--intf_type', 'wireguard', '--intf_name', '@4']
      validators:
        regex: {pattern: 'wg[0-9]+'}
      suggestors:
        interfaces: {prefix: wg}
      hints:
        wgN: WireGuard interface name
      children:

        detail:
          kind: leaf_node
          valueless: true
          description: Detailed kernel interface information
          command: ['interfaces.nvyr.op', 'show', '--intf_type', 'wireguard', '--intf_name', '@4', '--detail']

        statistics:
          kind: leaf_node
          valueless: true
          description: Interface packet and byte counters
          command: ['interfaces.nvyr.op', 'show', '--intf_type', 'wireguard', '--intf_name', '@4', '--statistics']

    macsec:
      kind: tag_node
      optional_value: true
      description: MACsec interface addresses and kernel state
      command: ['interfaces.nvyr.op', 'show', '--intf_type', 'macsec', '--intf_name', '@4']
      validators:
        regex: {pattern: 'macsec[0-9]+'}
      suggestors:
        interfaces: {prefix: macsec}
      hints:
        macsecN: MACsec interface name
      children:

        detail:
          kind: leaf_node
          valueless: true
          description: Detailed kernel interface information
          command: ['interfaces.nvyr.op', 'show', '--intf_type', 'macsec', '--intf_name', '@4', '--detail']

        statistics:
          kind: leaf_node
          valueless: true
          description: Interface packet and byte counters
          command: ['interfaces.nvyr.op', 'show', '--intf_type', 'macsec', '--intf_name', '@4', '--statistics']

    macvlan:
      kind: tag_node
      optional_value: true
      description: MACVLAN interface addresses and kernel state
      command: ['interfaces.nvyr.op', 'show', '--intf_type', 'macvlan', '--intf_name', '@4']
      validators:
        regex: {pattern: 'macvlan[0-9]{1,8}'}
      suggestors:
        interfaces: {prefix: macvlan}
      hints:
        macvlanN: MACVLAN interface name
      children:

        detail:
          kind: leaf_node
          valueless: true
          description: Detailed kernel interface information
          command: ['interfaces.nvyr.op', 'show', '--intf_type', 'macvlan', '--intf_name', '@4', '--detail']

        statistics:
          kind: leaf_node
          valueless: true
          description: Interface packet and byte counters
          command: ['interfaces.nvyr.op', 'show', '--intf_type', 'macvlan', '--intf_name', '@4', '--statistics']

    ethernet:
      kind: tag_node
      optional_value: true
      description: Ethernet interface information
      command: ['interfaces.nvyr.op', 'show', '--intf_type', 'ethernet', '--intf_name', '@4']
      suggestors:
        interfaces: {prefix: eth}
      validators:
        regex: {pattern: 'eth[0-9]+'}
      hints:
        ethN: Ethernet interface name
      children: # ethernet

        include_schema:
        - file: operational/interface_options.yaml.i
          as: null
          add:
            /detail/command: ['interfaces.nvyr.op', 'show', '--intf_type', 'ethernet', '--intf_name', '@4', '--detail']
            /statistics/command: ['interfaces.nvyr.op', 'show', '--intf_type', 'ethernet', '--intf_name', '@4', '--statistics']
            /offload/command: ['interfaces.nvyr.op', 'hardware', 'offload', '--intf_type', 'ethernet', '--intf_name', '@4']
            /queues/command: ['interfaces.nvyr.op', 'hardware', 'queues', '--intf_type', 'ethernet', '--intf_name', '@4']
            /hardware-statistics/command: ['interfaces.nvyr.op', 'hardware', 'hardware-statistics', '--intf_type', 'ethernet', '--intf_name', '@4']
            /transceiver/command: ['interfaces.nvyr.op', 'hardware', 'transceiver', '--intf_type', 'ethernet', '--intf_name', '@4']
