children:

  options:
    kind: node
    description: OSPF process options
    anchor: true
    children:

      router-id:
        kind: leaf_node
        description: Unique OSPF router ID
        validators:
          ipv4-address: {}
        hints:
          x.x.x.x: Unique OSPF router ID

      send-extra-data:
        kind: leaf_node
        description: Send additional OSPF information to Zebra
        valueless: true

      write-multiplier:
        kind: leaf_node
        description: Packets or interfaces processed per write cycle
        validators:
          integer-range:
            minimum: 1
            maximum: 100
        hints:
          1-100: Packets or interfaces processed per write cycle

  reference-bandwidth:
    kind: leaf_node
    description: Reference bandwidth in Mbps; keep consistent across the domain
    validators:
      integer-range:
        minimum: 1
        maximum: 4294967
    hints:
      1-4294967: Reference bandwidth in Mbps; keep consistent across the domain

  maximum-paths:
    kind: leaf_node
    description: Maximum equal-cost paths
    validators:
      integer-range:
        minimum: 1
        maximum: 256
    hints:
      1-256: Maximum equal-cost paths

  log-adjacency-changes:
    kind: node
    description: Log adjacency transitions
    anchor: true
    children:

      detail:
        kind: leaf_node
        description: Log every adjacency state transition
        valueless: true

  distance:
    kind: leaf_node
    description: Administrative distance
    validators:
      integer-range:
        minimum: 1
        maximum: 255
    hints:
      1-255: Administrative distance

  route-distance:
    kind: node
    description: Administrative distance by route type
    anchor: true
    children:

      intra-area:
        kind: leaf_node
        description: Administrative distance for intra-area routes
        validators:
          integer-range:
            minimum: 1
            maximum: 255
        hints:
          1-255: Administrative distance for intra-area routes

      inter-area:
        kind: leaf_node
        description: Administrative distance for inter-area routes
        validators:
          integer-range:
            minimum: 1
            maximum: 255
        hints:
          1-255: Administrative distance for inter-area routes

      external:
        kind: leaf_node
        description: Administrative distance for external routes
        validators:
          integer-range:
            minimum: 1
            maximum: 255
        hints:
          1-255: Administrative distance for external routes

  timers:
    kind: node
    description: Protocol scheduling timers
    anchor: true
    children:

      spf:
        kind: node
        description: Shortest-path-first calculation delays
        anchor: true
        children:

          delay:
            kind: leaf_node
            description: SPF delay in milliseconds
            validators:
              integer-range:
                minimum: 0
                maximum: 600000
            hints:
              0-600000: SPF delay in milliseconds

          initial-hold:
            kind: leaf_node
            description: SPF initial-hold in milliseconds
            validators:
              integer-range:
                minimum: 0
                maximum: 600000
            hints:
              0-600000: SPF initial-hold in milliseconds

          maximum-hold:
            kind: leaf_node
            description: SPF maximum-hold in milliseconds
            validators:
              integer-range:
                minimum: 0
                maximum: 600000
            hints:
              0-600000: SPF maximum-hold in milliseconds

      lsa-min-arrival:
        kind: leaf_node
        description: Minimum accepted interval between instances of an LSA, in milliseconds
        validators:
          integer-range:
            minimum: 0
            maximum: 600000
        hints:
          0-600000: Minimum accepted interval between instances of an LSA, in milliseconds

      aggregation:
        kind: leaf_node
        description: External summary aggregation delay, in seconds
        validators:
          integer-range:
            minimum: 5
            maximum: 1800
        hints:
          5-1800: External summary aggregation delay, in seconds

  default-information:
    kind: node
    description: Default route advertisement
    anchor: true
    children:

      originate:
        kind: node
        description: Originate a default route when one is available
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
                maximum: 16777214
            hints:
              0-16777214: Redistributed route metric

          metric-type:
            kind: leaf_node
            description: External route metric type
            validators:
              list:
                values: 1 2
            choices:
              '1': Add the internal cost to the external metric
              '2': Compare external metric before internal cost

          route-map:
            kind: leaf_node
            description: Configured route-map
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured route-map
            depends: policy-route-map
            suggestors:
              config-path:
                path: policy route-map

  redistribute:
    kind: node
    description: Import routes into OSPF
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
                maximum: 16777214
            hints:
              0-16777214: Redistributed route metric

          metric-type:
            kind: leaf_node
            description: External route metric type
            validators:
              list:
                values: 1 2
            choices:
              '1': Add the internal cost to the external metric
              '2': Compare external metric before internal cost

          route-map:
            kind: leaf_node
            description: Configured route-map
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured route-map
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
                maximum: 16777214
            hints:
              0-16777214: Redistributed route metric

          metric-type:
            kind: leaf_node
            description: External route metric type
            validators:
              list:
                values: 1 2
            choices:
              '1': Add the internal cost to the external metric
              '2': Compare external metric before internal cost

          route-map:
            kind: leaf_node
            description: Configured route-map
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured route-map
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
                maximum: 16777214
            hints:
              0-16777214: Redistributed route metric

          metric-type:
            kind: leaf_node
            description: External route metric type
            validators:
              list:
                values: 1 2
            choices:
              '1': Add the internal cost to the external metric
              '2': Compare external metric before internal cost

          route-map:
            kind: leaf_node
            description: Configured route-map
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured route-map
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
                maximum: 16777214
            hints:
              0-16777214: Redistributed route metric

          metric-type:
            kind: leaf_node
            description: External route metric type
            validators:
              list:
                values: 1 2
            choices:
              '1': Add the internal cost to the external metric
              '2': Compare external metric before internal cost

          route-map:
            kind: leaf_node
            description: Configured route-map
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured route-map
            depends: policy-route-map
            suggestors:
              config-path:
                path: policy route-map

      bgp:
        kind: node
        description: Redistribute BGP routes
        anchor: true
        children:

          metric:
            kind: leaf_node
            description: Redistributed route metric
            validators:
              integer-range:
                minimum: 0
                maximum: 16777214
            hints:
              0-16777214: Redistributed route metric

          metric-type:
            kind: leaf_node
            description: External route metric type
            validators:
              list:
                values: 1 2
            choices:
              '1': Add the internal cost to the external metric
              '2': Compare external metric before internal cost

          route-map:
            kind: leaf_node
            description: Configured route-map
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured route-map
            depends: policy-route-map
            suggestors:
              config-path:
                path: policy route-map

  graceful-restart:
    kind: node
    description: Enable restarting-router support
    anchor: true
    children:

      grace-period:
        kind: leaf_node
        description: Maximum graceful restart duration, in seconds
        validators:
          integer-range:
            minimum: 1
            maximum: 1800
        hints:
          1-1800: Maximum graceful restart duration, in seconds

  graceful-restart-helper:
    kind: node
    description: Help selected restarting neighbors
    anchor: true
    children:

      all:
        kind: leaf_node
        description: Help all neighbors
        valueless: true

      neighbor:
        kind: leaf_node
        description: Router ID allowed to use helper mode
        validators:
          ipv4-address: {}
        hints:
          x.x.x.x: Router ID allowed to use helper mode
        multi: true

      planned-only:
        kind: leaf_node
        description: Only assist planned restarts
        valueless: true

      supported-grace-time:
        kind: leaf_node
        description: Maximum accepted grace period, in seconds
        validators:
          integer-range:
            minimum: 10
            maximum: 1800
        hints:
          10-1800: Maximum accepted grace period, in seconds

      disable-strict-lsa-checking:
        kind: leaf_node
        description: Continue helper mode despite topology-changing LSAs
        valueless: true

  summary-address:
    kind: tag_node
    description: Prefix to summarize or suppress
    anchor: true
    validators:
      ipv6-prefix: {}
    hints:
      prefix: Prefix to summarize or suppress
    children:

      tag:
        kind: leaf_node
        description: External route tag
        validators:
          integer-range:
            minimum: 1
            maximum: 4294967295
        hints:
          1-4294967295: External route tag

      no-advertise:
        kind: leaf_node
        description: Suppress matching external routes
        valueless: true

      metric:
        kind: leaf_node
        description: Redistributed route metric
        validators:
          integer-range:
            minimum: 0
            maximum: 16777214
        hints:
          0-16777214: Redistributed route metric

      metric-type:
        kind: leaf_node
        description: External route metric type
        validators:
          list:
            values: 1 2
        choices:
          '1': Add the internal cost to the external metric
          '2': Compare external metric before internal cost

  stub-router:
    kind: leaf_node
    description: Advertise this router as unsuitable for transit
    valueless: true

  area:
    kind: tag_node
    description: OSPF area, in decimal or dotted decimal
    anchor: true
    validators:
      ospf-area: {}
    hints:
      0-4294967295|x.x.x.x: OSPF area, in decimal or dotted decimal
    children:

      stub:
        kind: node
        description: Stub area
        anchor: true
        children:

          no-summary:
            kind: leaf_node
            description: Suppress inter-area summaries
            valueless: true

      nssa:
        kind: node
        description: Not-so-stubby area
        anchor: true
        children:

          no-summary:
            kind: leaf_node
            description: Suppress inter-area summaries
            valueless: true

          default-information:
            kind: node
            description: NSSA default advertisement
            anchor: true
            children:

              originate:
                kind: node
                description: Originate an NSSA default
                anchor: true
                children:

                  metric:
                    kind: leaf_node
                    description: Redistributed route metric
                    validators:
                      integer-range:
                        minimum: 0
                        maximum: 16777214
                    hints:
                      0-16777214: Redistributed route metric

                  metric-type:
                    kind: leaf_node
                    description: External route metric type
                    validators:
                      list:
                        values: 1 2
                    choices:
                      '1': Add the internal cost to the external metric
                      '2': Compare external metric before internal cost

          range:
            kind: tag_node
            description: Prefix to summarize or suppress
            anchor: true
            validators:
              ipv6-prefix: {}
            hints:
              prefix: Prefix to summarize or suppress
            children:

              cost:
                kind: leaf_node
                description: Summary cost
                validators:
                  integer-range:
                    minimum: 0
                    maximum: 16777215
                hints:
                  0-16777215: Summary cost

              no-advertise:
                kind: leaf_node
                description: Suppress this NSSA range
                valueless: true

      range:
        kind: tag_node
        description: Prefix to summarize or suppress
        anchor: true
        validators:
          ipv6-prefix: {}
        hints:
          prefix: Prefix to summarize or suppress
        children:

          cost:
            kind: leaf_node
            description: Summary cost
            validators:
              integer-range:
                minimum: 0
                maximum: 16777215
            hints:
              0-16777215: Summary cost

          no-advertise:
            kind: leaf_node
            description: Suppress this inter-area range
            valueless: true

      import-list:
        kind: leaf_node
        description: Configured access-list
        validators:
          regex:
            pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
        hints:
          name: Configured access-list
        depends: policy-access-list-ipv6
        suggestors:
          config-path:
            path: policy access-list ipv6

      export-list:
        kind: leaf_node
        description: Configured access-list
        validators:
          regex:
            pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
        hints:
          name: Configured access-list
        depends: policy-access-list-ipv6
        suggestors:
          config-path:
            path: policy access-list ipv6

      filter-list:
        kind: node
        description: Filter inter-area summaries
        anchor: true
        children:

          in:
            kind: leaf_node
            description: Configured prefix-list
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured prefix-list
            depends: policy-prefix-list-ipv6
            suggestors:
              config-path:
                path: policy prefix-list ipv6

          out:
            kind: leaf_node
            description: Configured prefix-list
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured prefix-list
            depends: policy-prefix-list-ipv6
            suggestors:
              config-path:
                path: policy prefix-list ipv6

  interface:
    kind: tag_node
    description: Interface participating in OSPF
    anchor: true
    validators:
      regex:
        pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
    hints:
      interface: Interface participating in OSPF
    children:

      area:
        kind: leaf_node
        description: Area assigned to this interface
        validators:
          ospf-area: {}
        hints:
          area-id: Area assigned to this interface

      cost:
        kind: leaf_node
        description: Outgoing OSPF interface cost
        validators:
          integer-range:
            minimum: 1
            maximum: 65535
        hints:
          1-65535: Outgoing OSPF interface cost

      priority:
        kind: leaf_node
        description: Designated-router election priority
        validators:
          integer-range:
            minimum: 0
            maximum: 255
        hints:
          0-255: Designated-router election priority

      passive:
        kind: node
        description: Suppress OSPF adjacency formation
        anchor: true
        children:

          disable:
            kind: leaf_node
            description: Explicitly allow adjacency formation
            valueless: true

      hello-interval:
        kind: leaf_node
        description: OSPF hello-interval in seconds
        validators:
          integer-range:
            minimum: 1
            maximum: 65535
        hints:
          1-65535: OSPF hello-interval in seconds

      dead-interval:
        kind: leaf_node
        description: OSPF dead-interval in seconds
        validators:
          integer-range:
            minimum: 1
            maximum: 65535
        hints:
          1-65535: OSPF dead-interval in seconds

      retransmit-interval:
        kind: leaf_node
        description: OSPF retransmit-interval in seconds
        validators:
          integer-range:
            minimum: 1
            maximum: 65535
        hints:
          1-65535: OSPF retransmit-interval in seconds

      transmit-delay:
        kind: leaf_node
        description: OSPF transmit-delay in seconds
        validators:
          integer-range:
            minimum: 1
            maximum: 3600
        hints:
          1-3600: OSPF transmit-delay in seconds

      graceful-restart-hello-delay:
        kind: leaf_node
        description: Delay hellos while announcing a restart, in seconds
        validators:
          integer-range:
            minimum: 1
            maximum: 1800
        hints:
          1-1800: Delay hellos while announcing a restart, in seconds

      mtu-ignore:
        kind: leaf_node
        description: Ignore neighbor database-description MTU mismatch
        valueless: true

      authentication:
        kind: node
        description: OSPF packet authentication
        anchor: true
        children:

          key-chain:
            kind: leaf_node
            description: Configured key-chain
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured key-chain
            depends: policy-key-chain
            suggestors:
              config-path:
                path: policy key-chain

          key:
            kind: tag_node
            description: Manual authentication key identifier
            anchor: true
            validators:
              integer-range:
                minimum: 1
                maximum: 65535
            hints:
              1-65535: Manual authentication key identifier
            children:

              algorithm:
                kind: leaf_node
                description: Authentication hash algorithm
                validators:
                  list:
                    values: md5 hmac-sha-1 hmac-sha-256 hmac-sha-384 hmac-sha-512
                choices:
                  md5: MD5 authentication
                  hmac-sha-1: HMAC-SHA-1 authentication
                  hmac-sha-256: HMAC-SHA-256 authentication
                  hmac-sha-384: HMAC-SHA-384 authentication
                  hmac-sha-512: HMAC-SHA-512 authentication

              secret:
                kind: leaf_node
                description: Authentication secret (hidden by strip-private)
                validators:
                  regex:
                    pattern: '[^\s"\\]{1,128}'
                hints:
                  secret: Authentication secret (hidden by strip-private)
                secret: true

      network:
        kind: leaf_node
        description: OSPF link network type
        validators:
          list:
            values: broadcast point-to-point point-to-multipoint
        choices:
          broadcast: Multiaccess network with designated router election
          point-to-point: A link between two routers without designated router election
          point-to-multipoint: Treat neighbors as separate point-to-point links

      instance-id:
        kind: leaf_node
        description: On-wire OSPFv3 interface instance ID
        validators:
          integer-range:
            minimum: 0
            maximum: 255
        hints:
          0-255: On-wire OSPFv3 interface instance ID

      mtu:
        kind: leaf_node
        description: OSPF packet MTU in bytes
        validators:
          integer-range:
            minimum: 1
            maximum: 65535
        hints:
          1-65535: OSPF packet MTU in bytes

      advertise-prefix-list:
        kind: leaf_node
        description: Configured prefix-list
        validators:
          regex:
            pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
        hints:
          name: Configured prefix-list
        depends: policy-prefix-list-ipv6
        suggestors:
          config-path:
            path: policy prefix-list ipv6

      neighbor-options:
        kind: node
        description: Point-to-point and point-to-multipoint adjacency controls
        anchor: true
        children:

          disable-multicast-hello:
            kind: leaf_node
            description: Send only explicitly configured unicast hellos
            valueless: true

          configured-neighbors-only:
            kind: leaf_node
            description: Only form adjacencies with listed neighbors
            valueless: true

          connected-prefixes:
            kind: leaf_node
            description: Advertise attached prefixes in addition to local host routes
            validators:
              list:
                values: include exclude
            choices:
              include: Advertise connected prefixes on the link
              exclude: Exclude connected prefixes from link advertisements

      neighbor:
        kind: tag_node
        description: Static link-local neighbor
        anchor: true
        validators:
          ipv6-link-local-address: {}
        hints:
          fe80::address: Static link-local neighbor
        children:

          poll-interval:
            kind: leaf_node
            description: Unicast hello polling interval in seconds
            validators:
              integer-range:
                minimum: 1
                maximum: 65535
            hints:
              1-65535: Unicast hello polling interval in seconds

          cost:
            kind: leaf_node
            description: Outgoing cost through this neighbor
            validators:
              integer-range:
                minimum: 1
                maximum: 65535
            hints:
              1-65535: Outgoing cost through this neighbor
    depends: interface
    suggestors:
      interfaces: {}
