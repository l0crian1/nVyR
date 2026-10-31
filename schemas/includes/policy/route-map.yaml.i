route-map:
  kind: "tag_node"
  description: "Named route policy"
  anchor: true
  validators:
    regex:
      pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
  hints:
    name: "Named route policy"
  dependency: "policy-route-map"
  children:

    description:
      kind: "leaf_node"
      description: "Policy description"
      validators:
        text: {}
      hints:
        text: "Description; quote spaces"

    rule:
      kind: "tag_node"
      description: "Ordered route-map rule"
      anchor: true
      validators:
        mode: AND
        integer-range:
          minimum: 1
          maximum: 65535
        regex:
          pattern: "[1-9][0-9]*"
      hints:
        1-65535: "Rule sequence number; lower values run first"
      children:

        action:
          kind: "leaf_node"
          description: "Permit or deny matching routes"
          validators:
            list:
              values: "permit deny"
          choices:
            permit: "Permit matching routes"
            deny: "Deny matching routes"

        description:
          kind: "leaf_node"
          description: "Policy description"
          validators:
            text: {}
          hints:
            text: "Description; quote spaces"

        match:
          kind: "node"
          description: "Route matching conditions"
          anchor: true
          children:

            ipv4:
              kind: "node"
              description: "IPv4 route matches"
              anchor: true
              children:

                access-list:
                  kind: "leaf_node"
                  description: "IPv4 access-list used to match routes"
                  validators:
                    regex:
                      pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                  hints:
                    name: "Configured access-list"
                  depends: "policy-access-list-ipv4"
                  suggestors:
                    config-path:
                      path: "policy access-list ipv4"

                prefix-list:
                  kind: "leaf_node"
                  description: "IPv4 prefix-list used to match routes"
                  validators:
                    regex:
                      pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                  hints:
                    name: "Configured prefix-list"
                  depends: "policy-prefix-list-ipv4"
                  suggestors:
                    config-path:
                      path: "policy prefix-list ipv4"

                next-hop:
                  kind: "node"
                  description: "Match the route next-hop"
                  anchor: true
                  children:

                    access-list:
                      kind: "leaf_node"
                      description: IPv4 access-list used to match the route next hop
                      validators:
                        regex:
                          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                      hints:
                        name: "Configured access-list"
                      depends: "policy-access-list-ipv4"
                      suggestors:
                        config-path:
                          path: "policy access-list ipv4"

                    prefix-list:
                      kind: "leaf_node"
                      description: IPv4 prefix-list used to match the route next hop
                      validators:
                        regex:
                          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                      hints:
                        name: "Configured prefix-list"
                      depends: "policy-prefix-list-ipv4"
                      suggestors:
                        config-path:
                          path: "policy prefix-list ipv4"

                    address:
                      kind: "leaf_node"
                      description: "Exact next-hop address"
                      validators:
                        ipv4-address: {}
                      hints:
                        address: "Exact next-hop address"

            ipv6:
              kind: "node"
              description: "IPv6 route matches"
              anchor: true
              children:

                access-list:
                  kind: "leaf_node"
                  description: "IPv6 access-list used to match routes"
                  validators:
                    regex:
                      pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                  hints:
                    name: "Configured access-list"
                  depends: "policy-access-list-ipv6"
                  suggestors:
                    config-path:
                      path: "policy access-list ipv6"

                prefix-list:
                  kind: "leaf_node"
                  description: "IPv6 prefix-list used to match routes"
                  validators:
                    regex:
                      pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                  hints:
                    name: "Configured prefix-list"
                  depends: "policy-prefix-list-ipv6"
                  suggestors:
                    config-path:
                      path: "policy prefix-list ipv6"

                next-hop:
                  kind: "node"
                  description: "Match the route next-hop"
                  anchor: true
                  children:

                    access-list:
                      kind: "leaf_node"
                      description: IPv6 access-list used to match the route next hop
                      validators:
                        regex:
                          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                      hints:
                        name: "Configured access-list"
                      depends: "policy-access-list-ipv6"
                      suggestors:
                        config-path:
                          path: "policy access-list ipv6"

                    prefix-list:
                      kind: "leaf_node"
                      description: IPv6 prefix-list used to match the route next hop
                      validators:
                        regex:
                          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                      hints:
                        name: "Configured prefix-list"
                      depends: "policy-prefix-list-ipv6"
                      suggestors:
                        config-path:
                          path: "policy prefix-list ipv6"

                    address:
                      kind: "leaf_node"
                      description: "Exact next-hop address"
                      validators:
                        ipv6-address: {}
                      hints:
                        address: "Exact next-hop address"

            interface:
              kind: "leaf_node"
              description: "Match the outgoing interface"
              validators:
                regex:
                  pattern: "[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}"
              hints:
                name: "Interface name"
              depends: "interface"
              suggestors:
                interfaces: {}

            metric:
              kind: "leaf_node"
              description: "Match route metric"
              validators:
                integer-range:
                  minimum: 0
                  maximum: 4294967295
              hints:
                0-4294967295: "Match route metric"

            tag:
              kind: "leaf_node"
              description: "Match route tag"
              validators:
                integer-range:
                  minimum: 0
                  maximum: 4294967295
              hints:
                0-4294967295: "Match route tag"

            as-path-list:
              kind: "leaf_node"
              description: "Configured as-path-list"
              validators:
                regex:
                  pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
              hints:
                name: "Configured as-path-list"
              depends: "policy-as-path-list"
              suggestors:
                config-path:
                  path: policy as-path-list

            as-path-count:
              kind: "leaf_node"
              description: "Maximum AS-path length"
              validators:
                integer-range:
                  minimum: 0
                  maximum: 1028
              hints:
                0-1028: "Maximum AS-path length"

            local-preference:
              kind: "leaf_node"
              description: "Match BGP local preference"
              validators:
                integer-range:
                  minimum: 0
                  maximum: 4294967295
              hints:
                0-4294967295: "Match BGP local preference"

            community-list:
              kind: "tag_node"
              description: "Configured community-list"
              validators:
                regex:
                  pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
              hints:
                name: "Configured community-list"
              depends: "policy-community-list"
              suggestors:
                policy-community-lists:
                  large: false
              anchor: true
              children:

                exact-match:
                  kind: "leaf_node"
                  description: "Require the complete community set to match"
                  valueless: true

                any:
                  kind: "leaf_node"
                  description: "Match any community permitted by the list"
                  valueless: true

            large-community-list:
              kind: "tag_node"
              description: "Configured large-community-list"
              validators:
                regex:
                  pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
              hints:
                name: "Configured large-community-list"
              depends: "policy-large-community-list"
              suggestors:
                policy-community-lists:
                  large: true
              anchor: true
              children:

                exact-match:
                  kind: "leaf_node"
                  description: "Require the complete community set to match"
                  valueless: true

            peer:
              kind: "leaf_node"
              description: "Peer address, interface or peer-group name"
              validators:
                bgp-policy-peer: {}
              hints:
                peer: "Peer address, interface or peer-group name"

            source-peer:
              kind: "leaf_node"
              description: "Peer address, interface or peer-group name"
              validators:
                bgp-policy-peer: {}
              hints:
                peer: "Peer address, interface or peer-group name"

        set:
          kind: "node"
          description: "Attributes assigned to permitted routes"
          anchor: true
          children:

            metric:
              kind: "leaf_node"
              description: "Absolute value or signed adjustment"
              validators:
                bgp-policy-adjustment:
                  allow_zero_adjustment: false
              hints:
                value|+value|-value: "Absolute value or signed adjustment"

            local-preference:
              kind: "leaf_node"
              description: "Absolute value or signed adjustment"
              validators:
                bgp-policy-adjustment: {}
              hints:
                value|+value|-value: "Absolute value or signed adjustment"

            weight:
              kind: "leaf_node"
              description: "Set BGP weight"
              validators:
                integer-range:
                  minimum: 0
                  maximum: 4294967295
              hints:
                0-4294967295: "Set BGP weight"

            origin:
              kind: "leaf_node"
              description: "Set BGP origin"
              validators:
                list:
                  values: "igp egp incomplete"
              choices:
                igp: "IGP origin"
                egp: "EGP origin"
                incomplete: "Incomplete origin"

            ipv4:
              kind: "node"
              description: "IPv4 next-hop settings"
              anchor: true
              children:

                next-hop:
                  kind: "node"
                  description: "BGP next-hop settings"
                  anchor: true
                  children:

                    address:
                      kind: "leaf_node"
                      description: "IPv4 next-hop address"
                      validators:
                        ipv4-address: {}
                      hints:
                        x.x.x.x: "IPv4 next-hop address"

                    peer-address:
                      kind: "leaf_node"
                      description: "Use the peering address as the next hop"
                      valueless: true

                    unchanged:
                      kind: "leaf_node"
                      description: "Retain the advertised next hop"
                      valueless: true

            ipv6:
              kind: "node"
              description: "IPv6 next-hop settings"
              anchor: true
              children:

                next-hop:
                  kind: "node"
                  description: "BGP next-hop settings"
                  anchor: true
                  children:

                    global:
                      kind: "leaf_node"
                      description: "Global IPv6 next-hop address"
                      validators:
                        ipv6-global-next-hop: {}
                      hints:
                        x:x::x: "Global IPv6 next-hop address"

                    local:
                      kind: "leaf_node"
                      description: "Link-local IPv6 next-hop address"
                      validators:
                        ipv6-link-local-address: {}
                      hints:
                        fe80::x: "Link-local IPv6 next-hop address"

                    peer-address:
                      kind: "leaf_node"
                      description: "Use the peering address as the next hop"
                      valueless: true

                    prefer-global:
                      kind: "leaf_node"
                      description: "Prefer the received global IPv6 next hop"
                      valueless: true

            as-path:
              kind: "node"
              description: Modify the BGP AS path
              anchor: true
              children:

                prepend:
                  kind: "leaf_node"
                  description: "Prepend AS numbers in order, retaining duplicates"
                  validators:
                    as-path-sequence: {}
                  hints:
                    asns: "Quoted space-separated AS numbers"

                prepend-last-as:
                  kind: "leaf_node"
                  description: "Repeat the leftmost AS this many times"
                  validators:
                    integer-range:
                      minimum: 1
                      maximum: 10
                  hints:
                    1-10: "Repeat the leftmost AS this many times"

                exclude:
                  kind: "node"
                  description: "Remove selected AS numbers"
                  anchor: true
                  children:

                    as-number:
                      kind: "leaf_node"
                      description: "AS number to remove"
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 4294967295
                      hints:
                        1-4294967295: "AS number to remove"
                      multi: true

                    as-path-list:
                      kind: "leaf_node"
                      description: "Configured as-path-list"
                      validators:
                        regex:
                          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                      hints:
                        name: "Configured as-path-list"
                      depends: "policy-as-path-list"
                      suggestors:
                        config-path:
                          path: policy as-path-list

                    all:
                      kind: "leaf_node"
                      description: "Remove every AS number"
                      valueless: true

                replace:
                  kind: "node"
                  description: "Replace selected AS numbers"
                  anchor: true
                  children:

                    as-number:
                      kind: "leaf_node"
                      description: "AS number to replace"
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 4294967295
                      hints:
                        1-4294967295: "AS number to replace"

                    any:
                      kind: "leaf_node"
                      description: "Replace every AS number"
                      valueless: true

                    as-path-list:
                      kind: "leaf_node"
                      description: "Configured as-path-list"
                      validators:
                        regex:
                          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
                      hints:
                        name: "Configured as-path-list"
                      depends: "policy-as-path-list"
                      suggestors:
                        config-path:
                          path: policy as-path-list

                    replacement:
                      kind: "leaf_node"
                      description: "Replacement AS number; defaults to the local AS"
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 4294967295
                      hints:
                        1-4294967295: "Replacement AS number; defaults to the local AS"

            community:
              kind: "leaf_node"
              description: "Set BGP communities; additive retains existing communities"
              validators:
                bgp-community:
                  large: false
              hints:
                asn:value: "Community value"
              multi: true
              choices:
                no-export: "Do not advertise outside the local AS or confederation"
                no-advertise: "Do not advertise to any BGP peer"
                local-AS: "Do not advertise outside the local AS, including confederation peers"
                no-peer: "Do not advertise to bilateral peers"
                blackhole: "Request remote blackholing under the receiving policy"
                graceful-shutdown: "Signal planned session maintenance"
                accept-own: "Allow acceptance of reflected local routes under peer policy"
                llgr-stale: "Mark routes retained by long-lived graceful restart"
                no-llgr: "Exclude routes from long-lived graceful restart"
                accept-own-nexthop: "Allow routes whose next hop belongs to this router"
                route-filter-translated-v4: "IPv4 translated route-filter community"
                route-filter-v4: "IPv4 route-filter community"
                route-filter-translated-v6: "IPv6 translated route-filter community"
                route-filter-v6: "IPv6 route-filter community"
                additive: "Keep existing communities when adding these values"
                none: "Remove all communities"

            large-community:
              kind: "leaf_node"
              description: "Set BGP communities; additive retains existing communities"
              validators:
                bgp-community:
                  large: true
              hints:
                asn:value:value: "Community value"
              multi: true
              choices:
                additive: "Keep existing communities when adding these values"
                none: "Remove all communities"

            community-delete:
              kind: "leaf_node"
              description: "Delete communities permitted by this list"
              validators:
                regex:
                  pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
              hints:
                name: "Delete communities permitted by this list"
              depends: "policy-community-list"
              suggestors:
                policy-community-lists:
                  large: false

            large-community-delete:
              kind: "leaf_node"
              description: "Delete communities permitted by this list"
              validators:
                regex:
                  pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
              hints:
                name: "Delete communities permitted by this list"
              depends: "policy-large-community-list"
              suggestors:
                policy-community-lists:
                  large: true

        call:
          kind: "leaf_node"
          description: "Evaluate another route-map; a deny stops this policy"
          validators:
            regex:
              pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
          hints:
            name: "Evaluate another route-map; a deny stops this policy"
          depends: "policy-route-map"
          suggestors:
            config-path:
              path: policy route-map

        on-match:
          kind: "node"
          description: "Continue after a permitted match"
          anchor: true
          children:

            next:
              kind: "leaf_node"
              description: "Continue to the next rule"
              valueless: true

            goto:
              kind: "leaf_node"
              description: "Continue at the first rule at or beyond this sequence"
              validators:
                integer-range:
                  minimum: 1
                  maximum: 65535
              hints:
                1-65535: "Continue at the first rule at or beyond this sequence"
