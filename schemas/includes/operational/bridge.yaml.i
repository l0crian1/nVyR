bridge:
  kind: node
  description: Bridge interfaces and switching state
  command:
  - "bridge.nvyr.op"
  - "show"
  children:

    identifier:
      kind: tag_node
      description: Bridge interfaces and switching state
      command:
      - "bridge.nvyr.op"
      - "show"
      - "--bridge"
      - '@4'
      validators:
        regex:
          pattern: br[0-9]+
      suggestors:
        config-path:
          path: interfaces bridge
      hints:
        brN: Bridge interface name
      children:

        member:
          kind: node
          description: Bridge member ports
          command:
          - "bridge.nvyr.op"
          - "show"
          - "--bridge"
          - '@4'
          - "--section"
          - "member"
          children:

            identifier:
              kind: tag_node
              description: Bridge member ports
              command:
              - "bridge.nvyr.op"
              - "show"
              - "--bridge"
              - '@4'
              - "--section"
              - "member"
              - "--member"
              - '@6'
              validators:
                regex:
                  pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'
              suggestors:
                interfaces: {}
              hints:
                interface: Member interface name
              positional: true

        vlan:
          kind: leaf_node
          valueless: true
          description: Bridge and member VLAN memberships
          command:
          - "bridge.nvyr.op"
          - "show"
          - "--bridge"
          - '@4'
          - "--section"
          - "vlan"

        spanning-tree:
          kind: leaf_node
          valueless: true
          description: Spanning-tree state and root selection
          command:
          - "bridge.nvyr.op"
          - "show"
          - "--bridge"
          - '@4'
          - "--section"
          - "spanning-tree"

        mac:
          kind: leaf_node
          valueless: true
          description: Learned and static forwarding entries
          command:
          - "bridge.nvyr.op"
          - "show"
          - "--bridge"
          - '@4'
          - "--section"
          - "mac"

        multicast:
          kind: leaf_node
          valueless: true
          description: Multicast group memberships
          command:
          - "bridge.nvyr.op"
          - "show"
          - "--bridge"
          - '@4'
          - "--section"
          - "multicast"
      positional: true
