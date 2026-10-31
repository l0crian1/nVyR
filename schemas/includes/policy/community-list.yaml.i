community-list:
  kind: "node"
  description: "BGP community-lists"
  anchor: true
  children:

    standard:
      kind: "tag_node"
      description: "Named standard community-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named standard community-list"
      dependency: "policy-community-list"
      children:

        description:
          kind: "leaf_node"
          description: "Policy description"
          validators:
            text: {}
          hints:
            text: "Policy description"

        rule:
          kind: "tag_node"
          description: "Ordered policy rule"
          anchor: true
          validators:
            mode: AND
            integer-range:
              minimum: 1
              maximum: 4294967295
            regex:
              pattern: "[1-9][0-9]*"
          hints:
            1-4294967295: "Rule sequence number; lower values run first"
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

            community:
              kind: "leaf_node"
              description: "Community value to match"
              validators:
                bgp-community:
                  large: false
                  modifiers: false
              hints:
                asn:value: "Community value to match"
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

    expanded:
      kind: "tag_node"
      description: "Named expanded community-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named expanded community-list"
      dependency: "policy-community-list"
      children:

        description:
          kind: "leaf_node"
          description: "Policy description"
          validators:
            text: {}
          hints:
            text: "Policy description"

        rule:
          kind: "tag_node"
          description: "Ordered policy rule"
          anchor: true
          validators:
            mode: AND
            integer-range:
              minimum: 1
              maximum: 4294967295
            regex:
              pattern: "[1-9][0-9]*"
          hints:
            1-4294967295: "Rule sequence number; lower values run first"
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

            regex:
              kind: "leaf_node"
              description: "FRR regular expression; quote spaces"
              validators:
                frr-policy-regex: {}
              hints:
                regex: "FRR regular expression; quote spaces"
