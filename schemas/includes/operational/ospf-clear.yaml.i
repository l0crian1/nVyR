children:

  ip:
    kind: node
    description: IPv4
    children:

      ospf:
        kind: node
        description: Reset OSPF runtime state
        access: net-admin
        children:

          process:
            kind: node
            description: Reset the OSPF process
            command:
            - "ospf.nvyr.op"
            - "clear"
            - "@line"

          interface:
            kind: node
            description: Reset OSPF interfaces
            command:
            - "ospf.nvyr.op"
            - "clear"
            - "@line"
            children:

              name:
                kind: tag_node
                description: Interface to reset
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
                hints:
                  interface: Interface to reset
                children: {}
                command:
                - "ospf.nvyr.op"
                - "clear"
                - "@line"
                positional: true
                suggestors:
                  interfaces: {}

          neighbor:
            kind: node
            description: Reset OSPF neighbors
            command:
            - "ospf.nvyr.op"
            - "clear"
            - "@line"
            children:

              router-id:
                kind: tag_node
                description: Neighbor router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Neighbor router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "clear"
                - "@line"
                positional: true

          vrf:
            kind: tag_node
            description: Routing instance to reset
            validators:
              regex:
                pattern: '[A-Za-z][A-Za-z0-9_.-]{0,14}'
            hints:
              vrf: Routing instance to reset
            children:

              process:
                kind: node
                description: Reset the OSPF process
                command:
                - "ospf.nvyr.op"
                - "clear"
                - "@line"

              interface:
                kind: node
                description: Reset OSPF interfaces
                command:
                - "ospf.nvyr.op"
                - "clear"
                - "@line"
                children:

                  name:
                    kind: tag_node
                    description: Interface to reset
                    validators:
                      regex:
                        pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
                    hints:
                      interface: Interface to reset
                    children: {}
                    command:
                    - "ospf.nvyr.op"
                    - "clear"
                    - "@line"
                    positional: true
                    suggestors:
                      interfaces: {}

              neighbor:
                kind: node
                description: Reset OSPF neighbors
                command:
                - "ospf.nvyr.op"
                - "clear"
                - "@line"
                children:

                  router-id:
                    kind: tag_node
                    description: Neighbor router ID
                    validators:
                      ipv4-address: {}
                    hints:
                      router-id: Neighbor router ID
                    children: {}
                    command:
                    - "ospf.nvyr.op"
                    - "clear"
                    - "@line"
                    positional: true
            suggestors:
              config-path:
                path: vrf name

  ipv6:
    kind: node
    description: IPv6
    children:

      ospf:
        kind: node
        description: Reset OSPF runtime state
        access: net-admin
        children:

          process:
            kind: node
            description: Reset the OSPF process
            command:
            - "ospf.nvyr.op"
            - "clear"
            - "@line"

          interface:
            kind: node
            description: Reset OSPF interfaces
            command:
            - "ospf.nvyr.op"
            - "clear"
            - "@line"
            children:

              name:
                kind: tag_node
                description: Interface to reset
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
                hints:
                  interface: Interface to reset
                children: {}
                command:
                - "ospf.nvyr.op"
                - "clear"
                - "@line"
                positional: true
                suggestors:
                  interfaces: {}

          auth-counters:
            kind: node
            description: OSPFv3 authentication counters
            children:

              interface:
                kind: node
                description: Clear authentication errors
                command:
                - "ospf.nvyr.op"
                - "clear"
                - "@line"
                children:

                  name:
                    kind: tag_node
                    description: Interface to reset
                    validators:
                      regex:
                        pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
                    hints:
                      interface: Interface to reset
                    children: {}
                    command:
                    - "ospf.nvyr.op"
                    - "clear"
                    - "@line"
                    positional: true
                    suggestors:
                      interfaces: {}

          vrf:
            kind: tag_node
            description: Routing instance to reset
            validators:
              regex:
                pattern: '[A-Za-z][A-Za-z0-9_.-]{0,14}'
            hints:
              vrf: Routing instance to reset
            children:

              process:
                kind: node
                description: Reset the OSPF process
                command:
                - "ospf.nvyr.op"
                - "clear"
                - "@line"

              interface:
                kind: node
                description: Reset OSPF interfaces
                command:
                - "ospf.nvyr.op"
                - "clear"
                - "@line"
                children:

                  name:
                    kind: tag_node
                    description: Interface to reset
                    validators:
                      regex:
                        pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
                    hints:
                      interface: Interface to reset
                    children: {}
                    command:
                    - "ospf.nvyr.op"
                    - "clear"
                    - "@line"
                    positional: true
                    suggestors:
                      interfaces: {}

              auth-counters:
                kind: node
                description: OSPFv3 authentication counters
                children:

                  interface:
                    kind: node
                    description: Clear authentication errors
                    command:
                    - "ospf.nvyr.op"
                    - "clear"
                    - "@line"
                    children:

                      name:
                        kind: tag_node
                        description: Interface to reset
                        validators:
                          regex:
                            pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
                        hints:
                          interface: Interface to reset
                        children: {}
                        command:
                        - "ospf.nvyr.op"
                        - "clear"
                        - "@line"
                        positional: true
                        suggestors:
                          interfaces: {}
            suggestors:
              config-path:
                path: vrf name
