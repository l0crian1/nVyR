mpls:
  kind: node
  description: Reset MPLS protocol state
  children:

    ldp:
      kind: node
      description: Reset LDP sessions
      children:

        neighbor:
          kind: node
          description: Reset all LDP neighbors
          command:
            - 'mpls.nvyr.op'
            - 'clear'
            - '@line'
          children:

            address:
              kind: tag_node
              description: Neighbor transport address
              command:
                - 'mpls.nvyr.op'
                - 'clear'
                - '@line'
              positional: true
              validators:
                inet-address: {}
              hints:
                address: Neighbor transport address
  access: net-admin
