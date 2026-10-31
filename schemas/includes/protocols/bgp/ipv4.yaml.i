ipv4-unicast:
  kind: node
  description: IPv4 unicast advertisements
  anchor: true
  children:

    network:
      kind: tag_node
      anchor: true
      description: Advertise a prefix; routing-table presence is required only with network import-check enabled
      validators:
        network:
          version: 4
      hints:
        prefix: IPv4 network prefix
      children:

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
      description: Import routes from another routing source
      anchor: true
      children:

        connected:
          kind: node
          description: Import connected routes
          anchor: true
          children:

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

            metric:
              kind: leaf_node
              description: Metric assigned to redistributed routes
              validators:
                integer-range:
                  minimum: 0
                  maximum: 4294967295
              hints:
                0-4294967295: Metric assigned to redistributed routes

        static:
          kind: node
          description: Import static routes
          anchor: true
          children:

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

            metric:
              kind: leaf_node
              description: Metric assigned to redistributed routes
              validators:
                integer-range:
                  minimum: 0
                  maximum: 4294967295
              hints:
                0-4294967295: Metric assigned to redistributed routes

        kernel:
          kind: node
          description: Import kernel routes
          anchor: true
          children:

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

            metric:
              kind: leaf_node
              description: Metric assigned to redistributed routes
              validators:
                integer-range:
                  minimum: 0
                  maximum: 4294967295
              hints:
                0-4294967295: Metric assigned to redistributed routes

    aggregate-address:
      kind: tag_node
      anchor: true
      description: Aggregate contributing BGP routes
      validators:
        network:
          version: 4
      hints:
        prefix: IPv4 aggregate prefix
      children:

        summary-only:
          kind: leaf_node
          description: Suppress contributing more-specific routes
          valueless: true

        as-set:
          kind: leaf_node
          description: Preserve contributing AS paths as an AS set
          valueless: true

        route-map:
          kind: leaf_node
          description: Set aggregate attributes
          validators:
            regex:
              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
          hints:
            name: Set aggregate attributes
          depends: policy-route-map
          suggestors:
            config-path:
              path: policy route-map

        origin:
          kind: leaf_node
          description: Origin attribute of the aggregate
          validators:
            list:
              values: igp egp incomplete
          choices:
            igp: Interior origin
            egp: Exterior origin
            incomplete: Unspecified origin

        matching-med-only:
          kind: leaf_node
          description: Aggregate only when contributing routes have identical MED values
          valueless: true

        suppress-map:
          kind: leaf_node
          description: Select more-specific routes to suppress
          validators:
            regex:
              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
          hints:
            name: Select more-specific routes to suppress
          depends: policy-route-map
          suggestors:
            config-path:
              path: policy route-map

    maximum-paths:
      kind: node
      description: Maximum equal-cost paths
      anchor: true
      children:

        ebgp:
          kind: leaf_node
          description: External equal-cost paths
          validators:
            integer-range:
              minimum: 1
              maximum: 256
          hints:
            1-256: External equal-cost paths

        ibgp:
          kind: leaf_node
          description: Internal equal-cost paths
          validators:
            integer-range:
              minimum: 1
              maximum: 256
          hints:
            1-256: Internal equal-cost paths

    distance:
      kind: node
      description: Administrative distances for BGP routes
      anchor: true
      children:

        external:
          kind: leaf_node
          description: External BGP distance
          validators:
            integer-range:
              minimum: 1
              maximum: 255
          hints:
            1-255: External BGP distance

        internal:
          kind: leaf_node
          description: Internal BGP distance
          validators:
            integer-range:
              minimum: 1
              maximum: 255
          hints:
            1-255: Internal BGP distance

        local:
          kind: leaf_node
          description: Locally originated BGP distance
          validators:
            integer-range:
              minimum: 1
              maximum: 255
          hints:
            1-255: Locally originated BGP distance
