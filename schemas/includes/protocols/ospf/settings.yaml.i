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

      abr-type:
        kind: leaf_node
        description: Area border router behavior
        validators:
          list:
            values: cisco ibm shortcut standard
        choices:
          cisco: Cisco ABR behavior
          ibm: IBM ABR behavior
          shortcut: Shortcut ABR behavior
          standard: Standard ABR behavior

      opaque-lsa:
        kind: leaf_node
        description: Enable process-wide opaque LSA capability
        valueless: true

      rfc1583-compatibility:
        kind: leaf_node
        description: Use the older RFC 1583 external path preference
        valueless: true

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
            maximum: 5000
        hints:
          0-5000: Minimum accepted interval between instances of an LSA, in milliseconds

      aggregation:
        kind: leaf_node
        description: External summary aggregation delay, in seconds
        validators:
          integer-range:
            minimum: 5
            maximum: 1800
        hints:
          5-1800: External summary aggregation delay, in seconds

      lsa-generation:
        kind: leaf_node
        description: Minimum LSA origination interval in milliseconds
        validators:
          integer-range:
            minimum: 0
            maximum: 5000
        hints:
          0-5000: Minimum LSA origination interval in milliseconds

      refresh:
        kind: leaf_node
        description: Refresh worker interval in seconds
        validators:
          integer-range:
            minimum: 10
            maximum: 1800
        hints:
          10-1800: Refresh worker interval in seconds

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

      table:
        kind: tag_node
        description: Redistribute table source
        anchor: true
        validators:
          integer-range:
            minimum: 1
            maximum: 65535
        hints:
          source-id: Redistribute table source
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

      table-direct:
        kind: tag_node
        description: Redistribute table-direct source
        anchor: true
        validators:
          integer-range:
            minimum: 1
            maximum: 65535
        hints:
          source-id: Redistribute table-direct source
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
      ipv4-prefix: {}
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

  shutdown:
    kind: leaf_node
    description: Administratively shut down this OSPF process
    valueless: true

  passive-default:
    kind: leaf_node
    description: Make interfaces passive unless explicitly overridden
    valueless: true

  default-metric:
    kind: leaf_node
    description: Default redistributed metric
    validators:
      integer-range:
        minimum: 0
        maximum: 16777214
    hints:
      0-16777214: Default redistributed metric

  forwarding-address-self:
    kind: leaf_node
    description: Use this router as the external forwarding address
    valueless: true

  flood-reduction:
    kind: leaf_node
    description: Enable demand-circuit LSA flood reduction
    valueless: true

  disable-proactive-arp:
    kind: leaf_node
    description: Disable proactive ARP resolution
    valueless: true

  disable-socket-per-interface:
    kind: leaf_node
    description: Use a shared socket instead of per-interface transmit sockets
    valueless: true

  socket:
    kind: node
    description: OSPF socket buffers
    anchor: true
    children:

      buffer:
        kind: node
        description: Requested socket buffer sizes
        anchor: true
        children:

          send:
            kind: leaf_node
            description: Socket send buffer size in bytes
            validators:
              integer-range:
                minimum: 1
                maximum: 4000000000
            hints:
              1-4000000000: Socket send buffer size in bytes

          receive:
            kind: leaf_node
            description: Socket receive buffer size in bytes
            validators:
              integer-range:
                minimum: 1
                maximum: 4000000000
            hints:
              1-4000000000: Socket receive buffer size in bytes

          all:
            kind: leaf_node
            description: Set both send and receive socket buffer sizes in bytes
            validators:
              integer-range:
                minimum: 1
                maximum: 4000000000
            hints:
              1-4000000000: Send and receive socket buffer size in bytes

  router-info:
    kind: leaf_node
    description: Router Information LSA flooding scope
    validators:
      list:
        values: area as
    choices:
      area: Flood Router Information LSAs within each area
      as: Flood Router Information LSAs throughout the autonomous system

  max-metric:
    kind: node
    description: Discourage transit through this router
    anchor: true
    children:

      administrative:
        kind: leaf_node
        description: Advertise maximum transit cost indefinitely
        valueless: true

      on-startup:
        kind: leaf_node
        description: Maximum-cost startup duration in seconds
        validators:
          integer-range:
            minimum: 5
            maximum: 86400
        hints:
          5-86400: Maximum-cost startup duration in seconds

      on-shutdown:
        kind: leaf_node
        description: Maximum-cost shutdown duration in seconds
        validators:
          integer-range:
            minimum: 5
            maximum: 100
        hints:
          5-100: Maximum-cost shutdown duration in seconds

  neighbor:
    kind: tag_node
    description: Static NBMA neighbor
    anchor: true
    validators:
      ipv4-address: {}
    hints:
      x.x.x.x: Static NBMA neighbor
    children:

      priority:
        kind: leaf_node
        description: Neighbor DR priority
        validators:
          integer-range:
            minimum: 0
            maximum: 255
        hints:
          0-255: Neighbor DR priority

      poll-interval:
        kind: leaf_node
        description: Unreachable-neighbor polling interval in seconds
        validators:
          integer-range:
            minimum: 1
            maximum: 65535
        hints:
          1-65535: Unreachable-neighbor polling interval in seconds

  distribute-list:
    kind: node
    description: Filter redistributed advertisements
    anchor: true
    children:

      export:
        kind: tag_node
        description: Redistribution source to filter
        anchor: true
        validators:
          list:
            values: connected local static kernel bgp
        hints:
          source: Redistribution source to filter
        children:

          access-list:
            kind: leaf_node
            description: Configured access-list
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured access-list
            depends: policy-access-list-ipv4
            suggestors:
              config-path:
                path: policy access-list ipv4

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
              ipv4-prefix: {}
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

          translator-role:
            kind: leaf_node
            description: NSSA translator election role
            validators:
              list:
                values: candidate always never
            choices:
              candidate: Candidate
              always: Always
              never: Never

          suppress-forwarding-address:
            kind: leaf_node
            description: Clear forwarding address when translating Type-7 LSAs
            valueless: true

      range:
        kind: tag_node
        description: Prefix to summarize or suppress
        anchor: true
        validators:
          ipv4-prefix: {}
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

          substitute:
            kind: leaf_node
            description: Advertise this replacement prefix
            validators:
              ipv4-prefix: {}
            hints:
              prefix: Advertise this replacement prefix

      import-list:
        kind: leaf_node
        description: Configured access-list
        validators:
          regex:
            pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
        hints:
          name: Configured access-list
        depends: policy-access-list-ipv4
        suggestors:
          config-path:
            path: policy access-list ipv4

      export-list:
        kind: leaf_node
        description: Configured access-list
        validators:
          regex:
            pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
        hints:
          name: Configured access-list
        depends: policy-access-list-ipv4
        suggestors:
          config-path:
            path: policy access-list ipv4

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
            depends: policy-prefix-list-ipv4
            suggestors:
              config-path:
                path: policy prefix-list ipv4

          out:
            kind: leaf_node
            description: Configured prefix-list
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured prefix-list
            depends: policy-prefix-list-ipv4
            suggestors:
              config-path:
                path: policy prefix-list ipv4

      network:
        kind: leaf_node
        description: Select interfaces with addresses in this prefix
        validators:
          ipv4-prefix: {}
        hints:
          prefix: Select interfaces with addresses in this prefix
        multi: true

      authentication:
        kind: leaf_node
        description: Area authentication default
        validators:
          list:
            values: plaintext message-digest
        choices:
          plaintext: Plaintext
          message-digest: Message digest

      default-cost:
        kind: leaf_node
        description: Stub or NSSA default route cost
        validators:
          integer-range:
            minimum: 0
            maximum: 16777215
        hints:
          0-16777215: Stub or NSSA default route cost

      shortcut:
        kind: leaf_node
        description: Area shortcut behavior
        validators:
          list:
            values: default enable disable
        choices:
          default: Default
          enable: Enable
          disable: Disable

      flood-reduction:
        kind: leaf_node
        description: Enable flood reduction in this area
        valueless: true

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
            maximum: 65535
        hints:
          1-65535: OSPF transmit-delay in seconds

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

          none:
            kind: leaf_node
            description: Disable authentication on this interface
            valueless: true

          plaintext:
            kind: leaf_node
            description: Plaintext OSPF password, up to eight characters
            validators:
              regex:
                pattern: '[^\s"\\]{1,8}'
            hints:
              secret: Plaintext OSPF password, up to eight characters
            secret: true

          md5:
            kind: node
            description: MD5 authentication keys
            anchor: true
            children:

              key:
                kind: tag_node
                description: MD5 key identifier
                anchor: true
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 255
                hints:
                  1-255: MD5 key identifier
                children:

                  secret:
                    kind: leaf_node
                    description: MD5 password, up to sixteen characters
                    validators:
                      regex:
                        pattern: '[^\s"\\]{1,16}'
                    hints:
                      secret: MD5 password, up to sixteen characters
                    secret: true

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

      network:
        kind: node
        description: OSPF network type
        anchor: true
        children:

          broadcast:
            kind: leaf_node
            description: Broadcast multiaccess
            valueless: true

          non-broadcast:
            kind: leaf_node
            description: Non-broadcast multiaccess
            valueless: true

          point-to-point:
            kind: leaf_node
            description: Point-to-point
            valueless: true

          point-to-multipoint:
            kind: node
            description: Point-to-multipoint
            anchor: true
            children:

              non-broadcast:
                kind: leaf_node
                description: Use unicast hellos
                valueless: true

              delay-reflood:
                kind: leaf_node
                description: Delay reflooding received LSAs
                valueless: true

      fast-hello:
        kind: leaf_node
        description: Hellos per second with a one-second dead interval
        validators:
          integer-range:
            minimum: 2
            maximum: 20
        hints:
          2-20: Hellos per second with a one-second dead interval

      retransmit-window:
        kind: leaf_node
        description: Retransmit window in milliseconds
        validators:
          integer-range:
            minimum: 20
            maximum: 1000
        hints:
          20-1000: Retransmit window in milliseconds

      prefix-suppression:
        kind: leaf_node
        description: Suppress connected prefix advertisements
        valueless: true

      neighbor-filter:
        kind: leaf_node
        description: Configured prefix-list
        validators:
          regex:
            pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
        hints:
          name: Configured prefix-list
        depends: policy-prefix-list-ipv4
        suggestors:
          config-path:
            path: policy prefix-list ipv4

      disable-opaque-capability:
        kind: leaf_node
        description: Disable opaque capability on this interface
        valueless: true

      dead-timer-reset-any-control:
        kind: leaf_node
        description: Reset dead timer on any OSPF control packet
        valueless: true

      dscp:
        kind: node
        description: OSPF packet differentiated-services values
        anchor: true
        children:

          all:
            kind: leaf_node
            description: DSCP for all packets
            validators:
              integer-range:
                minimum: 0
                maximum: 63
            hints:
              0-63: DSCP for all packets

          low-control:
            kind: leaf_node
            description: DSCP for low-control packets
            validators:
              integer-range:
                minimum: 0
                maximum: 63
            hints:
              0-63: DSCP for low-control packets

      address:
        kind: tag_node
        description: Override settings for one local IPv4 address
        anchor: true
        validators:
          ipv4-address: {}
        hints:
          x.x.x.x: Override settings for one local IPv4 address
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
                maximum: 65535
            hints:
              1-65535: OSPF transmit-delay in seconds

          mtu-ignore:
            kind: leaf_node
            description: Ignore neighbor database-description MTU mismatch
            valueless: true

          authentication:
            kind: node
            description: OSPF packet authentication
            anchor: true
            children:

              none:
                kind: leaf_node
                description: Disable authentication on this interface
                valueless: true

              md5:
                kind: node
                description: MD5 authentication keys
                anchor: true
                children:

                  key:
                    kind: tag_node
                    description: MD5 key identifier
                    anchor: true
                    validators:
                      integer-range:
                        minimum: 1
                        maximum: 255
                    hints:
                      1-255: MD5 key identifier
                    children:

                      secret:
                        kind: leaf_node
                        description: MD5 password, up to sixteen characters
                        validators:
                          regex:
                            pattern: '[^\s"\\]{1,16}'
                        hints:
                          secret: MD5 password, up to sixteen characters
                        secret: true

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

          fast-hello:
            kind: leaf_node
            description: Hellos per second with a one-second dead interval
            validators:
              integer-range:
                minimum: 2
                maximum: 20
            hints:
              2-20: Hellos per second with a one-second dead interval

          retransmit-window:
            kind: leaf_node
            description: Retransmit window in milliseconds
            validators:
              integer-range:
                minimum: 20
                maximum: 1000
            hints:
              20-1000: Retransmit window in milliseconds

          prefix-suppression:
            kind: leaf_node
            description: Suppress connected prefix advertisements
            valueless: true

          neighbor-filter:
            kind: leaf_node
            description: Configured prefix-list
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Configured prefix-list
            depends: policy-prefix-list-ipv4
            suggestors:
              config-path:
                path: policy prefix-list ipv4

          disable-opaque-capability:
            kind: leaf_node
            description: Disable opaque capability on this interface
            valueless: true
    depends: interface
    suggestors:
      interfaces: {}
