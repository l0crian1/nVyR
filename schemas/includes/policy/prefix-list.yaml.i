prefix-list:
  kind: "node"
  description: "Routing prefix-lists"
  anchor: true
  children:

    ipv4:
      kind: "tag_node"
      description: "Named IPv4 prefix-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named IPv4 prefix-list"
      dependency: "policy-prefix-list-ipv4"
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

            description:
              kind: "leaf_node"
              description: "Policy description"
              validators:
                text: {}
              hints:
                text: "Description; quote spaces"

            prefix:
              kind: "leaf_node"
              description: "Network prefix to match"
              validators:
                network:
                  version: 4
              hints:
                x.x.x.x/x: "Network prefix"

            ge:
              kind: "leaf_node"
              description: "Minimum matching prefix length"
              validators:
                integer-range:
                  minimum: 0
                  maximum: 32
              hints:
                0-32: "Minimum matching prefix length"

            le:
              kind: "leaf_node"
              description: "Maximum matching prefix length"
              validators:
                integer-range:
                  minimum: 0
                  maximum: 32
              hints:
                0-32: "Maximum matching prefix length"

    ipv6:
      kind: "tag_node"
      description: "Named IPv6 prefix-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named IPv6 prefix-list"
      dependency: "policy-prefix-list-ipv6"
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

            description:
              kind: "leaf_node"
              description: "Policy description"
              validators:
                text: {}
              hints:
                text: "Description; quote spaces"

            prefix:
              kind: "leaf_node"
              description: "Network prefix to match"
              validators:
                network:
                  version: 6
              hints:
                "x:x::x/x": "Network prefix"

            ge:
              kind: "leaf_node"
              description: "Minimum matching prefix length"
              validators:
                integer-range:
                  minimum: 0
                  maximum: 128
              hints:
                0-128: "Minimum matching prefix length"

            le:
              kind: "leaf_node"
              description: "Maximum matching prefix length"
              validators:
                integer-range:
                  minimum: 0
                  maximum: 128
              hints:
                0-128: "Maximum matching prefix length"
