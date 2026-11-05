dns:
  kind: node
  description: DNS services
  children:

    forwarding:
      kind: node
      description: DNS forwarding service status
      children:

        statistics:
          kind: node
          description: Resolver counters and cache usage
          command:
          - 'dns_forwarding.nvyr.op'
          - 'show'
          - 'statistics'

        upstreams:
          kind: node
          description: Configured and learned upstream DNS servers
          command:
          - 'dns_forwarding.nvyr.op'
          - 'show'
          - 'upstreams'

        local-data:
          kind: node
          description: Published local A, AAAA and PTR records
          command:
          - 'dns_forwarding.nvyr.op'
          - 'show'
          - 'local-data'

        cache:
          kind: node
          description: Cached DNS resource records
          children:

            name:
              kind: leaf_node
              description: DNS name whose cached records should be displayed
              validators:
                dns-name: {}
              hints:
                domain: DNS name whose cached records should be displayed
              command:
              - 'dns_forwarding.nvyr.op'
              - 'show'
              - 'cache'
              - '--name'
              - '@6'
          command:
          - 'dns_forwarding.nvyr.op'
          - 'show'
          - 'cache'

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
          command:
          - 'dns_forwarding.nvyr.op'
          - 'show'
          - 'status'
          - '--vrf'
          - '@5'
          children:

            statistics:
              kind: node
              description: Resolver counters and cache usage
              command:
              - 'dns_forwarding.nvyr.op'
              - 'show'
              - 'statistics'
              - '--vrf'
              - '@5'

            upstreams:
              kind: node
              description: Configured and learned upstream DNS servers
              command:
              - 'dns_forwarding.nvyr.op'
              - 'show'
              - 'upstreams'
              - '--vrf'
              - '@5'

            local-data:
              kind: node
              description: Published local A, AAAA and PTR records
              command:
              - 'dns_forwarding.nvyr.op'
              - 'show'
              - 'local-data'
              - '--vrf'
              - '@5'

            cache:
              kind: node
              description: Cached DNS resource records
              children:

                name:
                  kind: leaf_node
                  description: DNS name whose cached records should be displayed
                  validators:
                    dns-name: {}
                  hints:
                    domain: DNS name whose cached records should be displayed
                  command:
                  - 'dns_forwarding.nvyr.op'
                  - 'show'
                  - 'cache'
                  - '--vrf'
                  - '@5'
                  - '--name'
                  - '@8'
              command:
              - 'dns_forwarding.nvyr.op'
              - 'show'
              - 'cache'
              - '--vrf'
              - '@5'
      command:
      - 'dns_forwarding.nvyr.op'
      - 'show'
      - 'status'
