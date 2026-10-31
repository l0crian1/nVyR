interfaces:
  kind: node
  description: Clear interface runtime state
  access: net-admin
  children:

    bridge:
      kind: tag_node
      description: Bridge whose learned MAC addresses will be removed
      validators:
        regex: {pattern: 'br[0-9]+'}
      suggestors:
        config-path: {path: 'interfaces bridge'}
      hints:
        brN: Bridge interface name
      children:

        learned-macs:
          kind: node
          description: Clear learned forwarding entries while preserving static entries
          command: ['bridge.nvyr.op', 'clear', '@4']
          children:

            interface:
              kind: leaf_node
              description: Clear learned entries on one bridge member
              command: ['bridge.nvyr.op', 'clear', '@4', '--member', '@7']
              validators:
                regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
              suggestors:
                interfaces: {}
              hints:
                interface: Member interface name

            vlan:
              kind: leaf_node
              description: Clear learned entries in one VLAN
              command: ['bridge.nvyr.op', 'clear', '@4', '--vlan', '@7']
              validators:
                integer-range: {minimum: 1, maximum: 4094}
              hints:
                1-4094: VLAN identifier
