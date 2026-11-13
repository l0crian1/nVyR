mpls:
  kind: node
  description: MPLS forwarding and label distribution
  children:

    status:
      kind: node
      description: MPLS platform status
      command:
        - 'mpls.nvyr.op'
        - 'show'
        - '@line'

    table:
      kind: node
      description: MPLS forwarding table
      command:
        - 'mpls.nvyr.op'
        - 'show'
        - '@line'
      children:

        label:
          kind: tag_node
          description: Incoming label
          command:
            - 'mpls.nvyr.op'
            - 'show'
            - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
          positional: true
          validators:
            integer-range:
              minimum: 16
              maximum: 1048575
          hints:
            16-1048575: Incoming label

        json:
          kind: node
          description: Native JSON output
          command:
            - 'mpls.nvyr.op'
            - 'show'
            - '@line'

    fec:
      kind: node
      description: Forwarding equivalence classes
      command:
        - 'mpls.nvyr.op'
        - 'show'
        - '@line'
      children:

        prefix:
          kind: tag_node
          description: Destination prefix
          command:
            - 'mpls.nvyr.op'
            - 'show'
            - '@line'
          positional: true
          validators:
            address: {}
          hints:
            prefix: Destination prefix

    ldp:
      kind: node
      description: Label Distribution Protocol
      children:

        binding:
          kind: node
          description: Label bindings
          command:
            - 'mpls.nvyr.op'
            - 'show'
            - '@line'
          children:

            local-label: &id001
              kind: leaf_node
              description: Locally assigned label
              validators:
                integer-range:
                  minimum: 0
                  maximum: 1048575
              hints:
                0-1048575: Locally assigned label
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
            remote-label: &id002
              kind: leaf_node
              description: Remotely assigned label
              validators:
                integer-range:
                  minimum: 0
                  maximum: 1048575
              hints:
                0-1048575: Remotely assigned label
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
            neighbor: &id003
              kind: leaf_node
              description: Neighbor LSR ID
              validators:
                ipv4-address: {}
              hints:
                lsr-id: Neighbor LSR ID
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
            detail: &id004
              kind: node
              description: Detailed bindings
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'

            prefix:
              kind: tag_node
              description: Destination prefix
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                local-label: *id001
                remote-label: *id002
                neighbor: *id003
                detail: *id004

                longer-prefixes:
                  kind: node
                  description: Include more-specific prefixes
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                  children:

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
              positional: true
              validators:
                address: {}
              hints:
                prefix: Destination prefix

            json:
              kind: node
              description: Native JSON output
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
          anchor: true

        discovery:
          kind: node
          description: LDP discovery
          command:
            - 'mpls.nvyr.op'
            - 'show'
            - '@line'
          children:

            detail:
              kind: node
              description: Detailed discovery
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'

            json:
              kind: node
              description: Native JSON output
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'

        interface:
          kind: node
          description: LDP interfaces
          command:
            - 'mpls.nvyr.op'
            - 'show'
            - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'

        ipv4:
          kind: node
          description: IPv4 LDP
          children:

            binding:
              kind: node
              description: Label bindings
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                local-label: &id005
                  kind: leaf_node
                  description: Locally assigned label
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 1048575
                  hints:
                    0-1048575: Locally assigned label
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                remote-label: &id006
                  kind: leaf_node
                  description: Remotely assigned label
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 1048575
                  hints:
                    0-1048575: Remotely assigned label
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                neighbor: &id007
                  kind: leaf_node
                  description: Neighbor LSR ID
                  validators:
                    ipv4-address: {}
                  hints:
                    lsr-id: Neighbor LSR ID
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                detail: &id008
                  kind: node
                  description: Detailed bindings
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                  children:

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'

                prefix:
                  kind: tag_node
                  description: Destination prefix
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                  children:

                    local-label: *id005
                    remote-label: *id006
                    neighbor: *id007
                    detail: *id008

                    longer-prefixes:
                      kind: node
                      description: Include more-specific prefixes
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'
                      children:

                        json:
                          kind: node
                          description: Native JSON output
                          command:
                            - 'mpls.nvyr.op'
                            - 'show'
                            - '@line'

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'
                  positional: true
                  validators:
                    address: {}
                  hints:
                    prefix: Destination prefix

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
              anchor: true

            discovery:
              kind: node
              description: LDP discovery
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                detail:
                  kind: node
                  description: Detailed discovery
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                  children:

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'

            interface:
              kind: node
              description: LDP interfaces
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'

        ipv6:
          kind: node
          description: IPv6 LDP
          children:

            binding:
              kind: node
              description: Label bindings
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                local-label: &id009
                  kind: leaf_node
                  description: Locally assigned label
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 1048575
                  hints:
                    0-1048575: Locally assigned label
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                remote-label: &id010
                  kind: leaf_node
                  description: Remotely assigned label
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 1048575
                  hints:
                    0-1048575: Remotely assigned label
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                neighbor: &id011
                  kind: leaf_node
                  description: Neighbor LSR ID
                  validators:
                    ipv4-address: {}
                  hints:
                    lsr-id: Neighbor LSR ID
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                detail: &id012
                  kind: node
                  description: Detailed bindings
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                  children:

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'

                prefix:
                  kind: tag_node
                  description: Destination prefix
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                  children:

                    local-label: *id009
                    remote-label: *id010
                    neighbor: *id011
                    detail: *id012

                    longer-prefixes:
                      kind: node
                      description: Include more-specific prefixes
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'
                      children:

                        json:
                          kind: node
                          description: Native JSON output
                          command:
                            - 'mpls.nvyr.op'
                            - 'show'
                            - '@line'

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'
                  positional: true
                  validators:
                    address: {}
                  hints:
                    prefix: Destination prefix

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
              anchor: true

            discovery:
              kind: node
              description: LDP discovery
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                detail:
                  kind: node
                  description: Detailed discovery
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                  children:

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'

            interface:
              kind: node
              description: LDP interfaces
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'

        neighbor:
          kind: node
          description: LDP neighbors
          command:
            - 'mpls.nvyr.op'
            - 'show'
            - '@line'
          children:

            detail:
              kind: node
              description: Detailed neighbor information
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'

            capabilities:
              kind: node
              description: Neighbor capabilities
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'

            lsr-id:
              kind: tag_node
              description: Neighbor LSR ID
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
              children:

                detail:
                  kind: node
                  description: Detailed neighbor information
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                  children:

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'

                capabilities:
                  kind: node
                  description: Neighbor capabilities
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
                  children:

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                        - 'mpls.nvyr.op'
                        - 'show'
                        - '@line'

                json:
                  kind: node
                  description: Native JSON output
                  command:
                    - 'mpls.nvyr.op'
                    - 'show'
                    - '@line'
              positional: true
              validators:
                ipv4-address: {}
              hints:
                lsr-id: Neighbor LSR ID

            json:
              kind: node
              description: Native JSON output
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'

        capabilities:
          kind: node
          description: Local capabilities
          command:
            - 'mpls.nvyr.op'
            - 'show'
            - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'

        igp-sync:
          kind: node
          description: IGP synchronization
          command:
            - 'mpls.nvyr.op'
            - 'show'
            - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
                - 'mpls.nvyr.op'
                - 'show'
                - '@line'
