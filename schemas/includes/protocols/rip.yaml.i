rip:
  kind: node
  description: RIPv1 and RIPv2 IPv4 routing
  anchor: true
  children:

    network:
      kind: leaf_node
      description: Enable RIP on interfaces within this network
      validators:
        ipv4-prefix: {}
      hints:
        prefix: Enable RIP on interfaces within this network
      multi: true

    interface:
      kind: tag_node
      description: Interface participating in RIP
      anchor: true
      validators:
        regex:
          pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
      hints:
        interface: Interface participating in RIP
      children:

        passive:
          kind: node
          description: Receive updates without sending them
          anchor: true
          children:

            disable:
              kind: leaf_node
              description: Send updates on this interface
              valueless: true

        split-horizon:
          kind: node
          description: Do not advertise routes back toward their source
          anchor: true
          children:

            disable:
              kind: leaf_node
              description: Disable split horizon
              valueless: true

            poisoned-reverse:
              kind: leaf_node
              description: Advertise reverse routes with an unreachable metric
              valueless: true

        distribute-list:
          kind: node
          description: Filter received or advertised routes
          anchor: true
          children:

            in:
              kind: node
              description: Filter received routes
              anchor: true
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

                prefix-list:
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
              kind: node
              description: Filter advertised routes
              anchor: true
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

                prefix-list:
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

        route-map:
          kind: node
          description: Apply routing policies to interface updates
          anchor: true
          children:

            in:
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

            out:
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

        offset-list:
          kind: node
          description: Add a metric to matching received or advertised routes
          anchor: true
          children:

            in:
              kind: node
              description: Metric offset for received routes
              anchor: true
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

                metric:
                  kind: leaf_node
                  description: Metric added to matching routes
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 16
                  hints:
                    0-16: Metric added to matching routes

            out:
              kind: node
              description: Metric offset for advertised routes
              anchor: true
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

                metric:
                  kind: leaf_node
                  description: Metric added to matching routes
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 16
                  hints:
                    0-16: Metric added to matching routes

        send-version:
          kind: leaf_node
          description: RIP versions sent on this interface
          validators:
            list:
              values: 1 2 both none
          choices:
            '1': RIPv1 only
            '2': RIPv2 only
            both: RIPv1 and RIPv2
            none: Do not send or receive this direction

        receive-version:
          kind: leaf_node
          description: RIP versions accepted on this interface
          validators:
            list:
              values: 1 2 both none
          choices:
            '1': RIPv1 only
            '2': RIPv2 only
            both: RIPv1 and RIPv2
            none: Do not send or receive this direction

        v2-broadcast:
          kind: leaf_node
          description: Send RIPv2 updates using broadcast instead of multicast
          valueless: true

        authentication:
          kind: node
          description: Authenticate RIP updates
          anchor: true
          children:

            mode:
              kind: leaf_node
              description: Authentication format
              validators:
                list:
                  values: text md5
              choices:
                text: Plaintext password
                md5: Keyed MD5 authentication

            password:
              kind: leaf_node
              description: RIP authentication password, up to sixteen characters
              validators:
                regex:
                  pattern: '[^\s"\\]{1,16}'
              hints:
                secret: RIP authentication password, up to sixteen characters
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

            md5-auth-length:
              kind: leaf_node
              description: MD5 authentication-length compatibility
              validators:
                list:
                  values: rfc old-ripd
              choices:
                rfc: RFC-compatible authentication length
                old-ripd: Compatibility with old ripd peers
      depends: interface
      suggestors:
        interfaces: {}

    redistribute:
      kind: node
      description: Import routes from another source
      anchor: true
      children:

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
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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

        isis:
          kind: node
          description: Redistribute isis routes
          anchor: true
          children:

            metric:
              kind: leaf_node
              description: Redistributed route metric
              validators:
                integer-range:
                  minimum: 0
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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
          description: Redistribute bgp routes
          anchor: true
          children:

            metric:
              kind: leaf_node
              description: Redistributed route metric
              validators:
                integer-range:
                  minimum: 0
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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

        eigrp:
          kind: node
          description: Redistribute eigrp routes
          anchor: true
          children:

            metric:
              kind: leaf_node
              description: Redistributed route metric
              validators:
                integer-range:
                  minimum: 0
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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

        nhrp:
          kind: node
          description: Redistribute nhrp routes
          anchor: true
          children:

            metric:
              kind: leaf_node
              description: Redistributed route metric
              validators:
                integer-range:
                  minimum: 0
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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

        babel:
          kind: node
          description: Redistribute babel routes
          anchor: true
          children:

            metric:
              kind: leaf_node
              description: Redistributed route metric
              validators:
                integer-range:
                  minimum: 0
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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

        openfabric:
          kind: node
          description: Redistribute openfabric routes
          anchor: true
          children:

            metric:
              kind: leaf_node
              description: Redistributed route metric
              validators:
                integer-range:
                  minimum: 0
                  maximum: 16
              hints:
                0-16: Redistributed route metric

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

    default-information:
      kind: node
      description: Default route advertisement
      anchor: true
      children:

        originate:
          kind: leaf_node
          description: Originate a default route
          valueless: true

    default-metric:
      kind: leaf_node
      description: Metric for redistributed routes without an explicit metric
      validators:
        integer-range:
          minimum: 1
          maximum: 16
      hints:
        1-16: Metric for redistributed routes without an explicit metric

    maximum-paths:
      kind: leaf_node
      description: Maximum equal-cost paths
      validators:
        integer-range:
          minimum: 1
          maximum: 255
      hints:
        1-255: Maximum equal-cost paths

    route:
      kind: leaf_node
      description: Originate a RIP route
      validators:
        ipv4-prefix: {}
      hints:
        prefix: Originate a RIP route
      multi: true

    distribute-list:
      kind: node
      description: Filter received or advertised routes
      anchor: true
      children:

        in:
          kind: node
          description: Filter received routes
          anchor: true
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

            prefix-list:
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
          kind: node
          description: Filter advertised routes
          anchor: true
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

            prefix-list:
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

    offset-list:
      kind: node
      description: Add a metric to matching received or advertised routes
      anchor: true
      children:

        in:
          kind: node
          description: Metric offset for received routes
          anchor: true
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

            metric:
              kind: leaf_node
              description: Metric added to matching routes
              validators:
                integer-range:
                  minimum: 0
                  maximum: 16
              hints:
                0-16: Metric added to matching routes

        out:
          kind: node
          description: Metric offset for advertised routes
          anchor: true
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

            metric:
              kind: leaf_node
              description: Metric added to matching routes
              validators:
                integer-range:
                  minimum: 0
                  maximum: 16
              hints:
                0-16: Metric added to matching routes

    timers:
      kind: node
      description: RIP protocol timers in seconds
      anchor: true
      children:

        update:
          kind: leaf_node
          description: Interval between periodic updates
          validators:
            integer-range:
              minimum: 1
              maximum: 32767
          hints:
            1-32767: Interval between periodic updates

        timeout:
          kind: leaf_node
          description: Time before a route expires
          validators:
            integer-range:
              minimum: 1
              maximum: 32767
          hints:
            1-32767: Time before a route expires

        garbage-collection:
          kind: leaf_node
          description: Time an expired route remains advertised as unreachable
          validators:
            integer-range:
              minimum: 1
              maximum: 32767
          hints:
            1-32767: Time an expired route remains advertised as unreachable

    version:
      kind: leaf_node
      description: Process-wide RIP version
      validators:
        list:
          values: 1 2
      choices:
        '1': RIPv1
        '2': RIPv2

    neighbor:
      kind: leaf_node
      description: Send unicast updates to this neighbor
      validators:
        ipv4-address: {}
      hints:
        x.x.x.x: Send unicast updates to this neighbor
      multi: true

    passive-default:
      kind: leaf_node
      description: Suppress updates unless an interface has passive disable
      valueless: true

    log-neighbor-changes:
      kind: leaf_node
      description: Log RIP neighbor changes
      valueless: true

    distance:
      kind: leaf_node
      description: Administrative distance for RIP routes
      validators:
        integer-range:
          minimum: 1
          maximum: 255
      hints:
        1-255: Administrative distance for RIP routes

    source-distance:
      kind: tag_node
      description: Override distance for routes learned from these source addresses
      anchor: true
      validators:
        ipv4-prefix: {}
      hints:
        prefix: Override distance for routes learned from these source addresses
      children:

        distance:
          kind: leaf_node
          description: Administrative distance
          validators:
            integer-range:
              minimum: 1
              maximum: 255
          hints:
            1-255: Administrative distance

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
  script:
    name: rip
    priority: 48
    register:
      vrf: default
    watch-before:
    - interfaces
    - policy
