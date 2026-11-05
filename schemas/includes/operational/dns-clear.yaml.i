dns:
  kind: node
  description: Clear DNS runtime state
  children:

    forwarding:
      kind: node
      description: Clear forwarding caches and statistics
      children:

        cache:
          kind: node
          description: Flush cached DNS answers
          children:

            all:
              kind: node
              description: Flush all cached answers
              command:
              - 'dns_forwarding.nvyr.op'
              - 'clear'
              - 'cache'
              - '--scope'
              - 'all'

            name:
              kind: leaf_node
              description: DNS name
              validators:
                dns-name: {}
              hints:
                domain: DNS name
              command:
              - 'dns_forwarding.nvyr.op'
              - 'clear'
              - 'cache'
              - '--scope'
              - 'name'
              - '--name'
              - '@6'

            domain:
              kind: leaf_node
              description: DNS suffix and all names below it
              validators:
                dns-name: {}
              hints:
                domain: DNS suffix and all names below it
              command:
              - 'dns_forwarding.nvyr.op'
              - 'clear'
              - 'cache'
              - '--scope'
              - 'domain'
              - '--name'
              - '@6'

        statistics:
          kind: node
          description: Reset DNS counters
          command:
          - 'dns_forwarding.nvyr.op'
          - 'clear'
          - 'statistics'

        vrf:
          kind: tag_node
          description: Routing instance
          validators:
            regex:
              pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'
          hints:
            vrf: Routing instance
          suggestors:
            config-path:
              path: vrf name
          children:

            cache:
              kind: node
              description: Flush cached DNS answers
              children:

                all:
                  kind: node
                  description: Flush all cached answers
                  command:
                  - 'dns_forwarding.nvyr.op'
                  - 'clear'
                  - 'cache'
                  - '--vrf'
                  - '@5'
                  - '--scope'
                  - 'all'

                name:
                  kind: leaf_node
                  description: DNS name
                  validators:
                    dns-name: {}
                  hints:
                    domain: DNS name
                  command:
                  - 'dns_forwarding.nvyr.op'
                  - 'clear'
                  - 'cache'
                  - '--vrf'
                  - '@5'
                  - '--scope'
                  - 'name'
                  - '--name'
                  - '@8'

                domain:
                  kind: leaf_node
                  description: DNS suffix and all names below it
                  validators:
                    dns-name: {}
                  hints:
                    domain: DNS suffix and all names below it
                  command:
                  - 'dns_forwarding.nvyr.op'
                  - 'clear'
                  - 'cache'
                  - '--vrf'
                  - '@5'
                  - '--scope'
                  - 'domain'
                  - '--name'
                  - '@8'

            statistics:
              kind: node
              description: Reset DNS counters
              command:
              - 'dns_forwarding.nvyr.op'
              - 'clear'
              - 'statistics'
              - '--vrf'
              - '@5'
  access: net-admin
