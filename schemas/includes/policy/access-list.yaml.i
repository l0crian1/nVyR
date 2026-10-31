access-list:
  kind: "node"
  description: "Routing access-lists"
  anchor: true
  children:

    ipv4:
      kind: "tag_node"
      description: "Named IPv4 access-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named IPv4 access-list"
      dependency: "policy-access-list-ipv4"
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

            any:
              kind: "leaf_node"
              description: "Match any route"
              valueless: true

            exact-match:
              kind: "leaf_node"
              description: "Require the exact prefix and length; only with prefix"
              valueless: true

            address:
              kind: "leaf_node"
              description: "Address to compare using wildcard-mask"
              validators:
                ipv4-address: {}
              hints:
                x.x.x.x: "Address to compare using wildcard-mask"

            wildcard-mask:
              kind: "leaf_node"
              description: "Inverse mask; zero bits compare and one bits ignore"
              validators:
                ipv4-address: {}
              hints:
                x.x.x.x: "Inverse mask; zero bits compare and one bits ignore"

    ipv6:
      kind: "tag_node"
      description: "Named IPv6 access-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named IPv6 access-list"
      dependency: "policy-access-list-ipv6"
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

            any:
              kind: "leaf_node"
              description: "Match any route"
              valueless: true

            exact-match:
              kind: "leaf_node"
              description: "Require the exact prefix and length; only with prefix"
              valueless: true
