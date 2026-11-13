ldp:
  kind: node
  description: Label Distribution Protocol
  anchor: true
  children:

    options:
      kind: node
      description: LDP process settings
      anchor: true
      children:

        router-id:
          kind: leaf_node
          description: IPv4-style LSR identifier
          validators:
            ldp-address: {}
          hints:
            router-id: IPv4-style LSR identifier

        ordered-control:
          kind: leaf_node
          description: Use ordered label distribution control
          valueless: true

        allow-broken-lsps:
          kind: leaf_node
          description: Allow label installation before the downstream path is complete
          valueless: true

        wait-for-sync:
          kind: leaf_node
          description: Wait for synchronization in seconds
          validators:
            integer-range:
              minimum: 1
              maximum: 10000
          hints:
            1-10000: Wait for synchronization in seconds

        dual-stack:
          kind: node
          description: Dual-stack interoperability
          anchor: true
          children:

            transport-preference:
              kind: leaf_node
              description: Preferred TCP transport family
              validators:
                list:
                  values: ipv4 ipv6
              hints:
                value: Preferred TCP transport family
              choices:
                ipv4: ipv4
                ipv6: ipv6

            cisco-interop:
              kind: leaf_node
              description: Use Cisco dual-stack interoperability mode
              valueless: true

    discovery:
      kind: node
      description: LDP discovery
      anchor: true
      children:

        hello:
          kind: node
          description: Link discovery timers
          anchor: true
          children:

            interval:
              kind: leaf_node
              description: Hello interval in seconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 65535
              hints:
                1-65535: Hello interval in seconds

            holdtime:
              kind: leaf_node
              description: Hello holdtime in seconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 65535
              hints:
                1-65535: Hello holdtime in seconds

        targeted-hello:
          kind: node
          description: Targeted discovery timers
          anchor: true
          children:

            interval:
              kind: leaf_node
              description: Hello interval in seconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 65535
              hints:
                1-65535: Hello interval in seconds

            holdtime:
              kind: leaf_node
              description: Hello holdtime in seconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 65535
              hints:
                1-65535: Hello holdtime in seconds

    neighbor:
      kind: tag_node
      description: Neighbor LSR identifier
      anchor: true
      validators:
        ldp-address: {}
      hints:
        lsr-id: Neighbor IPv4 LSR identifier
      children:

        password:
          kind: leaf_node
          description: TCP MD5 password, up to 79 characters
          validators:
            regex:
              pattern: '[^\s"\\]{1,79}'
          hints:
            secret: TCP MD5 password, up to 79 characters
          secret: true

        session-holdtime:
          kind: leaf_node
          description: Session holdtime in seconds
          validators:
            integer-range:
              minimum: 15
              maximum: 65535
          hints:
            15-65535: Session holdtime in seconds

        ttl-security:
          kind: node
          description: Neighbor TTL security override
          anchor: true
          children:

            disable:
              kind: leaf_node
              description: Disable TTL checking for this neighbor
              valueless: true

            hops:
              kind: leaf_node
              description: Maximum distance in hops
              validators:
                integer-range:
                  minimum: 1
                  maximum: 254
              hints:
                1-254: Maximum distance in hops

    address-family:
      kind: node
      description: LDP address families
      anchor: true
      children:

        ipv4:
          kind: node
          description: ipv4 LDP
          anchor: true
          children:

            transport-address:
              kind: leaf_node
              description: Local LDP transport address
              validators:
                ldp-address:
                  version: 4
              hints:
                address: Local LDP transport address

            session-holdtime:
              kind: leaf_node
              description: Session holdtime in seconds
              validators:
                integer-range:
                  minimum: 15
                  maximum: 65535
              hints:
                15-65535: Session holdtime in seconds

            ttl-security:
              kind: node
              description: Generalized TTL security
              anchor: true
              children:

                disable:
                  kind: leaf_node
                  description: Disable TTL checking
                  valueless: true

            discovery:
              kind: node
              description: LDP discovery
              anchor: true
              children:

                hello:
                  kind: node
                  description: Link discovery timers
                  anchor: true
                  children:

                    interval:
                      kind: leaf_node
                      description: Hello interval in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello interval in seconds

                    holdtime:
                      kind: leaf_node
                      description: Hello holdtime in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello holdtime in seconds

                targeted-hello:
                  kind: node
                  description: Targeted discovery timers
                  anchor: true
                  children:

                    interval:
                      kind: leaf_node
                      description: Hello interval in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello interval in seconds

                    holdtime:
                      kind: leaf_node
                      description: Hello holdtime in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello holdtime in seconds

                    accept:
                      kind: node
                      description: Accept targeted hellos
                      anchor: true
                      children:

                        from-access-list:
                          kind: leaf_node
                          description: Restrict accepted targeted hello source addresses
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Restrict accepted targeted hello source addresses
                          depends: policy-access-list-ipv4
                          suggestors:
                            config-path:
                              path: policy access-list ipv4

            interface:
              kind: tag_node
              description: LDP discovery interface
              anchor: true
              validators:
                regex:
                  pattern: '[A-Za-z][A-Za-z0-9_.-]{0,14}'
              hints:
                interface: LDP discovery interface
              suggestors:
                interfaces: {}
              children:

                hello:
                  kind: node
                  description: Interface discovery timers
                  anchor: true
                  children:

                    interval:
                      kind: leaf_node
                      description: Hello interval in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello interval in seconds

                    holdtime:
                      kind: leaf_node
                      description: Hello holdtime in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello holdtime in seconds

                disable-establish-hello:
                  kind: leaf_node
                  description: Do not send extra hellos when a session establishes
                  valueless: true

            targeted-neighbor:
              kind: leaf_node
              description: Remote targeted discovery address
              validators:
                ldp-address:
                  version: 4
                  link_local: false
              hints:
                address: Remote targeted discovery address
              multi: true

            label:
              kind: node
              description: Label distribution policy
              anchor: true
              children:

                local:
                  kind: node
                  description: Local label policy
                  anchor: true
                  children:

                    allocate:
                      kind: node
                      description: Restrict label allocation
                      anchor: true
                      children:

                        host-routes:
                          kind: leaf_node
                          description: Allocate labels only for host routes
                          valueless: true

                        access-list:
                          kind: leaf_node
                          description: Allocate labels for matching prefixes
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Allocate labels for matching prefixes
                          depends: policy-access-list-ipv4
                          suggestors:
                            config-path:
                              path: policy access-list ipv4

                    advertise:
                      kind: node
                      description: Restrict label advertisements
                      anchor: true
                      children:

                        to-access-list:
                          kind: leaf_node
                          description: Filter neighbor LSR IDs
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Filter neighbor LSR IDs
                          depends: policy-access-list-ipv4
                          suggestors:
                            config-path:
                              path: policy access-list ipv4

                        for-access-list:
                          kind: leaf_node
                          description: Filter advertised prefixes
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Filter advertised prefixes
                          depends: policy-access-list-ipv4
                          suggestors:
                            config-path:
                              path: policy access-list ipv4

                        explicit-null:
                          kind: node
                          description: Advertise explicit null labels
                          anchor: true
                          children:

                            for-access-list:
                              kind: leaf_node
                              description: Advertise explicit null only for matching prefixes
                              validators:
                                regex:
                                  pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                              hints:
                                name: Advertise explicit null only for matching prefixes
                              depends: policy-access-list-ipv4
                              suggestors:
                                config-path:
                                  path: policy access-list ipv4

                remote:
                  kind: node
                  description: Remote label policy
                  anchor: true
                  children:

                    accept:
                      kind: node
                      description: Restrict accepted label mappings
                      anchor: true
                      children:

                        from-access-list:
                          kind: leaf_node
                          description: Filter neighbor LSR IDs
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Filter neighbor LSR IDs
                          depends: policy-access-list-ipv4
                          suggestors:
                            config-path:
                              path: policy access-list ipv4

                        for-access-list:
                          kind: leaf_node
                          description: Filter accepted prefixes
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Filter accepted prefixes
                          depends: policy-access-list-ipv4
                          suggestors:
                            config-path:
                              path: policy access-list ipv4

        ipv6:
          kind: node
          description: ipv6 LDP
          anchor: true
          children:

            transport-address:
              kind: leaf_node
              description: Local LDP transport address
              validators:
                ldp-address:
                  version: 6
              hints:
                address: Local LDP transport address

            session-holdtime:
              kind: leaf_node
              description: Session holdtime in seconds
              validators:
                integer-range:
                  minimum: 15
                  maximum: 65535
              hints:
                15-65535: Session holdtime in seconds

            ttl-security:
              kind: node
              description: Generalized TTL security
              anchor: true
              children:

                disable:
                  kind: leaf_node
                  description: Disable TTL checking
                  valueless: true

            discovery:
              kind: node
              description: LDP discovery
              anchor: true
              children:

                hello:
                  kind: node
                  description: Link discovery timers
                  anchor: true
                  children:

                    interval:
                      kind: leaf_node
                      description: Hello interval in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello interval in seconds

                    holdtime:
                      kind: leaf_node
                      description: Hello holdtime in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello holdtime in seconds

                targeted-hello:
                  kind: node
                  description: Targeted discovery timers
                  anchor: true
                  children:

                    interval:
                      kind: leaf_node
                      description: Hello interval in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello interval in seconds

                    holdtime:
                      kind: leaf_node
                      description: Hello holdtime in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello holdtime in seconds

                    accept:
                      kind: node
                      description: Accept targeted hellos
                      anchor: true
                      children:

                        from-access-list:
                          kind: leaf_node
                          description: Restrict accepted targeted hello source addresses
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Restrict accepted targeted hello source addresses
                          depends: policy-access-list-ipv6
                          suggestors:
                            config-path:
                              path: policy access-list ipv6

            interface:
              kind: tag_node
              description: LDP discovery interface
              anchor: true
              validators:
                regex:
                  pattern: '[A-Za-z][A-Za-z0-9_.-]{0,14}'
              hints:
                interface: LDP discovery interface
              suggestors:
                interfaces: {}
              children:

                hello:
                  kind: node
                  description: Interface discovery timers
                  anchor: true
                  children:

                    interval:
                      kind: leaf_node
                      description: Hello interval in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello interval in seconds

                    holdtime:
                      kind: leaf_node
                      description: Hello holdtime in seconds
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 65535
                      hints:
                        1-65535: Hello holdtime in seconds

                disable-establish-hello:
                  kind: leaf_node
                  description: Do not send extra hellos when a session establishes
                  valueless: true

            targeted-neighbor:
              kind: leaf_node
              description: Remote targeted discovery address
              validators:
                ldp-address:
                  version: 6
                  link_local: false
              hints:
                address: Remote targeted discovery address
              multi: true

            label:
              kind: node
              description: Label distribution policy
              anchor: true
              children:

                local:
                  kind: node
                  description: Local label policy
                  anchor: true
                  children:

                    allocate:
                      kind: node
                      description: Restrict label allocation
                      anchor: true
                      children:

                        host-routes:
                          kind: leaf_node
                          description: Allocate labels only for host routes
                          valueless: true

                        access-list:
                          kind: leaf_node
                          description: Allocate labels for matching prefixes
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Allocate labels for matching prefixes
                          depends: policy-access-list-ipv6
                          suggestors:
                            config-path:
                              path: policy access-list ipv6

                    advertise:
                      kind: node
                      description: Restrict label advertisements
                      anchor: true
                      children:

                        to-access-list:
                          kind: leaf_node
                          description: Filter neighbor LSR IDs
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Filter neighbor LSR IDs
                          depends: policy-access-list-ipv4
                          suggestors:
                            config-path:
                              path: policy access-list ipv4

                        for-access-list:
                          kind: leaf_node
                          description: Filter advertised prefixes
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Filter advertised prefixes
                          depends: policy-access-list-ipv6
                          suggestors:
                            config-path:
                              path: policy access-list ipv6

                        explicit-null:
                          kind: node
                          description: Advertise explicit null labels
                          anchor: true
                          children:

                            for-access-list:
                              kind: leaf_node
                              description: Advertise explicit null only for matching prefixes
                              validators:
                                regex:
                                  pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                              hints:
                                name: Advertise explicit null only for matching prefixes
                              depends: policy-access-list-ipv6
                              suggestors:
                                config-path:
                                  path: policy access-list ipv6

                remote:
                  kind: node
                  description: Remote label policy
                  anchor: true
                  children:

                    accept:
                      kind: node
                      description: Restrict accepted label mappings
                      anchor: true
                      children:

                        from-access-list:
                          kind: leaf_node
                          description: Filter neighbor LSR IDs
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Filter neighbor LSR IDs
                          depends: policy-access-list-ipv4
                          suggestors:
                            config-path:
                              path: policy access-list ipv4

                        for-access-list:
                          kind: leaf_node
                          description: Filter accepted prefixes
                          validators:
                            regex:
                              pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                          hints:
                            name: Filter accepted prefixes
                          depends: policy-access-list-ipv6
                          suggestors:
                            config-path:
                              path: policy access-list ipv6
  script:
    name: ldp
    priority: 49
    watch-before:
      - interfaces
      - policy
      - protocols mpls
