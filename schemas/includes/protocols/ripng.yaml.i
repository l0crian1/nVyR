ripng:
  kind: node
  description: RIPng IPv6 routing
  anchor: true
  children:

    network:
      kind: leaf_node
      description: Enable RIPNG on interfaces within this network
      validators:
        ipv6-prefix: {}
      hints:
        prefix: Enable RIPNG on interfaces within this network
      multi: true

    interface:
      kind: tag_node
      description: Interface participating in RIPNG
      anchor: true
      validators:
        regex:
          pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
      hints:
        interface: Interface participating in RIPNG
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
                  depends: policy-access-list-ipv6
                  suggestors:
                    config-path:
                      path: policy access-list ipv6

                prefix-list:
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
                  depends: policy-access-list-ipv6
                  suggestors:
                    config-path:
                      path: policy access-list ipv6

                prefix-list:
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
                  depends: policy-access-list-ipv6
                  suggestors:
                    config-path:
                      path: policy access-list ipv6

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
                  depends: policy-access-list-ipv6
                  suggestors:
                    config-path:
                      path: policy access-list ipv6

                metric:
                  kind: leaf_node
                  description: Metric added to matching routes
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 16
                  hints:
                    0-16: Metric added to matching routes
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
      description: Originate a RIPNG route
      validators:
        ipv6-prefix: {}
      hints:
        prefix: Originate a RIPNG route
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
              depends: policy-access-list-ipv6
              suggestors:
                config-path:
                  path: policy access-list ipv6

            prefix-list:
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
              depends: policy-access-list-ipv6
              suggestors:
                config-path:
                  path: policy access-list ipv6

            prefix-list:
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
              depends: policy-access-list-ipv6
              suggestors:
                config-path:
                  path: policy access-list ipv6

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
              depends: policy-access-list-ipv6
              suggestors:
                config-path:
                  path: policy access-list ipv6

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
              maximum: 65535
          hints:
            1-65535: Interval between periodic updates

        timeout:
          kind: leaf_node
          description: Time before a route expires
          validators:
            integer-range:
              minimum: 1
              maximum: 65535
          hints:
            1-65535: Time before a route expires

        garbage-collection:
          kind: leaf_node
          description: Time an expired route remains advertised as unreachable
          validators:
            integer-range:
              minimum: 1
              maximum: 65535
          hints:
            1-65535: Time an expired route remains advertised as unreachable

    aggregate-address:
      kind: leaf_node
      description: Advertise an aggregate for matching RIPng routes
      validators:
        ipv6-prefix: {}
      hints:
        prefix: Advertise an aggregate for matching RIPng routes
      multi: true
  script:
    name: ripng
    priority: 49
    register:
      vrf: default
    watch-before:
    - interfaces
    - policy
