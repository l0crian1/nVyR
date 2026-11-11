isis:
  kind: node
  description: IS-IS IPv4 and IPv6 routing
  anchor: true
  children:

    net:
      kind: leaf_node
      description: Network Entity Title containing area, system ID and zero selector
      validators:
        isis-net: {}
      hints:
        NET: For example 49.0001.0000.0000.0001.00
      multi: true

    options:
      kind: node
      description: IS-IS process behavior
      anchor: true
      children:

        level:
          kind: leaf_node
          description: Routing levels
          choices:
            level-1: Intra-area routing
            level-2: Inter-area routing
            level-1-2: Both routing levels

        metric-style:
          kind: leaf_node
          description: Metric encoding
          choices:
            narrow: Legacy six-bit metrics
            transition: Advertise legacy and extended metrics
            wide: Extended 24-bit metrics

        disable-dynamic-hostname:
          kind: leaf_node
          description: Do not advertise the router hostname
          valueless: true

        advertise-high-metrics:
          kind: leaf_node
          description: Discourage transit by advertising high interface metrics
          valueless: true

        advertise-passive-only:
          kind: leaf_node
          description: Advertise only prefixes on passive interfaces
          valueless: true

        overload:
          kind: node
          description: Discourage transit through this router
          anchor: true
          children:

            administrative:
              kind: leaf_node
              description: Set overload until removed
              valueless: true

            on-startup:
              kind: leaf_node
              description: Startup overload duration in seconds
              validators:
                integer-range:
                  minimum: 0
                  maximum: 86400
              hints:
                0-86400: Startup overload duration in seconds

        attached-bit:
          kind: node
          description: L1/L2 attached-bit handling
          anchor: true
          children:

            send:
              kind: leaf_node
              description: Advertise attachment to other areas
              valueless: true

            ignore:
              kind: leaf_node
              description: Ignore received attached bits
              valueless: true

        purge-originator:
          kind: leaf_node
          description: Include purge originator information
          valueless: true

        lsp-mtu:
          kind: leaf_node
          description: Maximum generated LSP size in bytes
          validators:
            integer-range:
              minimum: 128
              maximum: 4352
          hints:
            128-4352: Maximum generated LSP size in bytes

        log-adjacency-changes:
          kind: leaf_node
          description: Log adjacency changes
          valueless: true

        log-pdu-drops:
          kind: leaf_node
          description: Log dropped protocol packets
          valueless: true

    level:
      kind: tag_node
      description: Settings for one routing level
      anchor: true
      children:

        authentication:
          kind: node
          description: IS-IS authentication
          anchor: true
          children:

            mode:
              kind: leaf_node
              description: Authentication wire format
              choices:
                plaintext: Plaintext authentication
                md5: HMAC-MD5 authentication

            password:
              kind: leaf_node
              description: IS-IS authentication secret
              validators:
                regex:
                  pattern: '[^\s"\\\x00-\x1f\x7f]{1,254}'
              hints:
                secret: Authentication password
              secret: true

            snp:
              kind: leaf_node
              description: Sequence-number PDU authentication
              choices:
                send-only: Send authenticated SNPs without requiring them on receipt
                validate: Send and validate authenticated SNPs

        timers:
          kind: node
          description: LSP and SPF timing
          anchor: true
          children:

            lsp-generation:
              kind: leaf_node
              description: Minimum LSP generation interval in seconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 120
              hints:
                1-120: Minimum LSP generation interval in seconds

            lsp-refresh:
              kind: leaf_node
              description: LSP refresh interval in seconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 65235
              hints:
                1-65235: LSP refresh interval in seconds

            lsp-lifetime:
              kind: leaf_node
              description: Maximum LSP lifetime in seconds
              validators:
                integer-range:
                  minimum: 350
                  maximum: 65535
              hints:
                350-65535: Maximum LSP lifetime in seconds

            spf-interval:
              kind: leaf_node
              description: Minimum SPF interval in seconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 120
              hints:
                1-120: Minimum SPF interval in seconds

        fast-reroute:
          kind: node
          description: Local loop-free alternate selection
          anchor: true
          children:

            priority-limit:
              kind: leaf_node
              description: Lowest protected prefix priority
              choices:
                critical: critical
                high: high
                medium: medium

            disable-load-sharing:
              kind: leaf_node
              description: Use a single backup rather than sharing load
              valueless: true

            tiebreaker:
              kind: tag_node
              description: Ordered LFA selection criterion
              anchor: true
              children:

                type:
                  kind: leaf_node
                  description: Backup selection criterion
                  choices:
                    downstream: downstream
                    lowest-backup-metric: lowest-backup-metric
                    node-protecting: node-protecting
              validators:
                integer-range:
                  minimum: 1
                  maximum: 255
              hints:
                1-255: Ordered LFA selection criterion
      validators:
        list:
          values: level-1 level-2
      choices:
        level-1: Intra-area routing
        level-2: Inter-area routing

    spf:
      kind: node
      description: SPF scheduling and prefix priority
      anchor: true
      children:

        delay:
          kind: node
          description: IETF SPF backoff timers in milliseconds
          anchor: true
          children:

            initial:
              kind: leaf_node
              description: Initial delay
              validators:
                integer-range:
                  minimum: 0
                  maximum: 60000
              hints:
                0-60000: Initial delay

            short:
              kind: leaf_node
              description: Short delay
              validators:
                integer-range:
                  minimum: 0
                  maximum: 60000
              hints:
                0-60000: Short delay

            long:
              kind: leaf_node
              description: Long delay
              validators:
                integer-range:
                  minimum: 0
                  maximum: 60000
              hints:
                0-60000: Long delay

            hold-down:
              kind: leaf_node
              description: Hold-down duration
              validators:
                integer-range:
                  minimum: 0
                  maximum: 60000
              hints:
                0-60000: Hold-down duration

            time-to-learn:
              kind: leaf_node
              description: Learning interval
              validators:
                integer-range:
                  minimum: 0
                  maximum: 60000
              hints:
                0-60000: Learning interval

        prefix-priority:
          kind: tag_node
          description: Priority assigned to matching prefixes
          anchor: true
          children:

            access-list:
              kind: leaf_node
              description: IPv4 access-list selecting prefixes
              validators:
                regex:
                  pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
              hints:
                name: IPv4 access-list selecting prefixes
              depends: policy-access-list-ipv4
              suggestors:
                config-path:
                  path: policy access-list ipv4
          validators:
            list:
              values: critical high medium
          choices:
            critical: critical
            high: high
            medium: medium

    topology:
      kind: tag_node
      description: Additional IS-IS topology
      anchor: true
      children:

        overload:
          kind: leaf_node
          description: Set overload for this topology
          valueless: true
      validators:
        list:
          values: ipv6-unicast ipv4-multicast ipv6-multicast ipv4-management ipv6-management ipv6-dstsrc
      choices:
        ipv6-unicast: IPv6 unicast reachability
        ipv4-multicast: ipv4-multicast
        ipv6-multicast: ipv6-multicast
        ipv4-management: ipv4-management
        ipv6-management: ipv6-management
        ipv6-dstsrc: ipv6-dstsrc

    address-family:
      kind: node
      description: Address-family route policy
      anchor: true
      children:

        ipv4-unicast:
          kind: node
          description: IPV4 unicast route advertisements
          anchor: true
          children:

            level:
              kind: tag_node
              description: Advertisement level
              anchor: true
              children:

                default-originate:
                  kind: node
                  description: Originate a default route
                  anchor: true
                  children:

                    always:
                      kind: leaf_node
                      description: Originate even without a default route
                      valueless: true

                    metric:
                      kind: leaf_node
                      description: Redistributed route metric
                      validators:
                        integer-range:
                          minimum: 0
                          maximum: 16777215
                      hints:
                        0-16777215: Redistributed route metric

                    route-map:
                      kind: leaf_node
                      description: Redistribution route-map
                      validators:
                        regex:
                          pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                      hints:
                        name: Redistribution route-map
                      depends: policy-route-map
                      suggestors:
                        config-path:
                          path: policy route-map

                redistribute:
                  kind: node
                  description: Import routes from other sources
                  anchor: true
                  children:

                    connected:
                      kind: node
                      description: Redistribute connected routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    kernel:
                      kind: node
                      description: Redistribute kernel routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    local:
                      kind: node
                      description: Redistribute local routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    static:
                      kind: node
                      description: Redistribute static routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    bgp:
                      kind: node
                      description: Redistribute bgp routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    ospf:
                      kind: node
                      description: Redistribute ospf routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    rip:
                      kind: node
                      description: Redistribute rip routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    table:
                      kind: tag_node
                      description: Redistribute a kernel routing table
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        table-id: Redistribute a kernel routing table
              validators:
                list:
                  values: level-1 level-2
              choices:
                level-1: Intra-area routing
                level-2: Inter-area routing

        ipv6-unicast:
          kind: node
          description: IPV6 unicast route advertisements
          anchor: true
          children:

            level:
              kind: tag_node
              description: Advertisement level
              anchor: true
              children:

                default-originate:
                  kind: node
                  description: Originate a default route
                  anchor: true
                  children:

                    always:
                      kind: leaf_node
                      description: Originate even without a default route
                      valueless: true

                    metric:
                      kind: leaf_node
                      description: Redistributed route metric
                      validators:
                        integer-range:
                          minimum: 0
                          maximum: 16777215
                      hints:
                        0-16777215: Redistributed route metric

                    route-map:
                      kind: leaf_node
                      description: Redistribution route-map
                      validators:
                        regex:
                          pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                      hints:
                        name: Redistribution route-map
                      depends: policy-route-map
                      suggestors:
                        config-path:
                          path: policy route-map

                redistribute:
                  kind: node
                  description: Import routes from other sources
                  anchor: true
                  children:

                    connected:
                      kind: node
                      description: Redistribute connected routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    kernel:
                      kind: node
                      description: Redistribute kernel routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    local:
                      kind: node
                      description: Redistribute local routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    static:
                      kind: node
                      description: Redistribute static routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    bgp:
                      kind: node
                      description: Redistribute bgp routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    ospfv3:
                      kind: node
                      description: Redistribute ospfv3 routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    ripng:
                      kind: node
                      description: Redistribute ripng routes
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map

                    table:
                      kind: tag_node
                      description: Redistribute a kernel routing table
                      anchor: true
                      children:

                        metric:
                          kind: leaf_node
                          description: Redistributed route metric
                          validators:
                            integer-range:
                              minimum: 0
                              maximum: 16777215
                          hints:
                            0-16777215: Redistributed route metric

                        route-map:
                          kind: leaf_node
                          description: Redistribution route-map
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Redistribution route-map
                          depends: policy-route-map
                          suggestors:
                            config-path:
                              path: policy route-map
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        table-id: Redistribute a kernel routing table
              validators:
                list:
                  values: level-1 level-2
              choices:
                level-1: Intra-area routing
                level-2: Inter-area routing

    interface:
      kind: tag_node
      description: Participating interface
      anchor: true
      children:

        address-family:
          kind: leaf_node
          description: Address family carried on this interface
          choices:
            ipv4-unicast: IPv4 unicast reachability
            ipv6-unicast: IPv6 unicast reachability
          multi: true

        circuit-type:
          kind: leaf_node
          description: Adjacency levels
          choices:
            level-1: Intra-area routing
            level-2: Inter-area routing
            level-1-2: Both routing levels

        network:
          kind: leaf_node
          description: Link network type
          choices:
            broadcast: Broadcast multiaccess
            point-to-point: Point-to-point

        passive:
          kind: node
          description: Advertise prefixes without forming adjacencies
          anchor: true
          children:

            disable:
              kind: leaf_node
              description: Explicitly allow adjacency formation
              valueless: true

        authentication:
          kind: node
          description: IS-IS authentication
          anchor: true
          children:

            mode:
              kind: leaf_node
              description: Authentication wire format
              choices:
                plaintext: Plaintext authentication
                md5: HMAC-MD5 authentication

            password:
              kind: leaf_node
              description: IS-IS authentication secret
              validators:
                regex:
                  pattern: '[^\s"\\\x00-\x1f\x7f]{1,254}'
              hints:
                secret: Authentication password
              secret: true

        hello-padding:
          kind: leaf_node
          description: Padding of hello packets
          choices:
            always: Pad every hello
            during-adjacency-formation: Pad hellos until adjacency is established
            disabled: Do not pad hellos

        disable-three-way-handshake:
          kind: leaf_node
          description: Disable the point-to-point three-way handshake
          valueless: true

        topology:
          kind: tag_node
          description: Interface topology participation
          anchor: true
          children:

            disable:
              kind: leaf_node
              description: Disable this topology on the interface
              valueless: true
          validators:
            list:
              values: standard ipv6-unicast ipv4-multicast ipv6-multicast ipv4-management ipv6-management ipv6-dstsrc
          choices:
            standard: standard
            ipv6-unicast: IPv6 unicast reachability
            ipv4-multicast: ipv4-multicast
            ipv6-multicast: ipv6-multicast
            ipv4-management: ipv4-management
            ipv6-management: ipv6-management
            ipv6-dstsrc: ipv6-dstsrc

        level:
          kind: tag_node
          description: Interface settings for one level
          anchor: true
          children:

            metric:
              kind: leaf_node
              description: Outgoing interface metric
              validators:
                integer-range:
                  minimum: 0
                  maximum: 16777215
              hints:
                0-16777215: Outgoing interface metric

            priority:
              kind: leaf_node
              description: Designated intermediate system priority
              validators:
                integer-range:
                  minimum: 0
                  maximum: 127
              hints:
                0-127: Designated intermediate system priority

            timers:
              kind: node
              description: Protocol packet intervals
              anchor: true
              children:

                hello-interval:
                  kind: leaf_node
                  description: Hello interval in seconds
                  validators:
                    integer-range:
                      minimum: 1
                      maximum: 600
                  hints:
                    1-600: Hello interval in seconds

                hello-multiplier:
                  kind: leaf_node
                  description: Holding-time multiplier
                  validators:
                    integer-range:
                      minimum: 2
                      maximum: 100
                  hints:
                    2-100: Holding-time multiplier

                csnp-interval:
                  kind: leaf_node
                  description: Complete SNP interval in seconds
                  validators:
                    integer-range:
                      minimum: 1
                      maximum: 600
                  hints:
                    1-600: Complete SNP interval in seconds

                psnp-interval:
                  kind: leaf_node
                  description: Partial SNP interval in seconds
                  validators:
                    integer-range:
                      minimum: 1
                      maximum: 120
                  hints:
                    1-120: Partial SNP interval in seconds

            fast-reroute:
              kind: node
              description: Interface local protection
              anchor: true
              children:

                lfa:
                  kind: node
                  description: Enable local loop-free alternate protection
                  anchor: true
                  children:

                    exclude-interface:
                      kind: leaf_node
                      description: Exclude an interface from backup selection
                      validators:
                        regex:
                          pattern: '[A-Za-z_][A-Za-z0-9_.:-]{0,14}'
                      hints:
                        interface: Excluded interface
                      multi: true
          validators:
            list:
              values: level-1 level-2
          choices:
            level-1: Intra-area routing
            level-2: Inter-area routing
      validators:
        regex:
          pattern: '[A-Za-z_][A-Za-z0-9_.:-]{0,14}'
      hints:
        interface: Participating interface
  script:
    name: isis
    priority: 46
    register:
      vrf: default
    watch-before:
    - interfaces
    - policy
