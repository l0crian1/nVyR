clear:
  kind: node
  description: Reset operational state
  children: # clear

    include_schema:
    - file: operational/bgp-clear.yaml.i
    - file: operational/bridge-clear.yaml.i
    - file: operational/policy-clear.yaml.i

    conntrack:
      kind: node
      access: net-admin
      description: Clear all tracked connections and NAT state after confirmation
      command: ['conntrack.nvyr.op', 'clear']
      stream: true

    firewall:
      kind: node
      access: net-admin
      description: Clear firewall runtime state and statistics
      children: # firewall

        counter:
          kind: leaf_node
          description: Reset a named firewall counter
          command: ['firewall.nvyr.op', 'clear_counter', '@4']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Counter group name
          suggestors:
            config-path: {path: 'firewall group counter-group'}

        quota:
          kind: leaf_node
          description: Reset a named firewall quota's consumed bytes
          command: ['firewall.nvyr.op', 'clear_quota', '@4']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Quota group name
          suggestors:
            config-path: {path: 'firewall group quota-group'}

        group:
          kind: node
          description: Clear learned members from dynamic groups
          children:

            address-group:
              kind: node
              description: Clear dynamic address-group members
              children:

                ipv4:
                  kind: tag_node
                  description: Dynamic IPv4 group name
                  validators:
                    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
                  hints:
                    name: Dynamic group name
                  suggestors:
                    dynamic-firewall-groups: {kind: address-group, family: ipv4}
                  children:

                    learned:
                      kind: leaf_node
                      valueless: true
                      description: Clear all learned members
                      command: ['firewall.nvyr.op', 'clear_group', '@line']

                    member:
                      kind: leaf_node
                      description: Remove one learned address
                      command: ['firewall.nvyr.op', 'clear_group', '@line']
                      validators:
                        ipv4-address: {}
                      hints:
                        address: Exact learned IPv4 address

                ipv6:
                  kind: tag_node
                  description: Dynamic IPv6 group name
                  validators:
                    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
                  hints:
                    name: Dynamic group name
                  suggestors:
                    dynamic-firewall-groups: {kind: address-group, family: ipv6}
                  children:

                    learned:
                      kind: leaf_node
                      valueless: true
                      description: Clear all learned members
                      command: ['firewall.nvyr.op', 'clear_group', '@line']

                    member:
                      kind: leaf_node
                      description: Remove one learned address
                      command: ['firewall.nvyr.op', 'clear_group', '@line']
                      validators:
                        ipv6-address: {}
                      hints:
                        address: Exact learned IPv6 address

            match-group:
              kind: node
              description: Clear dynamic match-group members
              children:

                ipv4:
                  kind: tag_node
                  description: Dynamic IPv4 group name
                  validators:
                    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
                  hints:
                    name: Dynamic group name
                  suggestors:
                    dynamic-firewall-groups: {kind: match-group, family: ipv4}
                  children:

                    learned:
                      kind: leaf_node
                      valueless: true
                      description: Clear all learned members
                      command: ['firewall.nvyr.op', 'clear_group', '@line']

                    member:
                      kind: node
                      anchor: true
                      description: Remove one exact learned combination of match fields
                      command: ['firewall.nvyr.op', 'clear_group', '@line']
                      children:

                        include_schema:
                        - file: operational/firewall_member_ipv4.yaml.i
                          as: null

                inet:
                  kind: tag_node
                  description: Dynamic Family-neutral group name
                  validators:
                    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
                  hints:
                    name: Dynamic group name
                  suggestors:
                    dynamic-firewall-groups: {kind: match-group, family: inet}
                  children:

                    learned:
                      kind: leaf_node
                      valueless: true
                      description: Clear all learned members
                      command: ['firewall.nvyr.op', 'clear_group', '@line']

                    member:
                      kind: node
                      anchor: true
                      description: Remove one exact learned combination of match fields
                      command: ['firewall.nvyr.op', 'clear_group', '@line']
                      children:

                        include_schema:
                        - file: operational/firewall_member_inet.yaml.i
                          as: null

                ipv6:
                  kind: tag_node
                  description: Dynamic IPv6 group name
                  validators:
                    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
                  hints:
                    name: Dynamic group name
                  suggestors:
                    dynamic-firewall-groups: {kind: match-group, family: ipv6}
                  children:

                    learned:
                      kind: leaf_node
                      valueless: true
                      description: Clear all learned members
                      command: ['firewall.nvyr.op', 'clear_group', '@line']

                    member:
                      kind: node
                      anchor: true
                      description: Remove one exact learned combination of match fields
                      command: ['firewall.nvyr.op', 'clear_group', '@line']
                      children:

                        include_schema:
                        - file: operational/firewall_member_ipv6.yaml.i
                          as: null
