extended-community-list:
  kind: "node"
  description: "BGP extended-community-lists"
  anchor: true
  children:

    standard:
      kind: "tag_node"
      description: "Named standard extended-community-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named standard extended-community-list"
      dependency: "policy-extended-community-list"
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

            route-target:
              kind: "leaf_node"
              description: "Route target to match"
              validators:
                bgp-rd-rt: {}
              hints:
                asn:value: "Route target to match"
              multi: true

            site-of-origin:
              kind: leaf_node
              description: Site-of-origin community to match
              hints:
                soo: ASN:number or IPv4:number
              validators:
                bgp-rd-rt: {}
              multi: true

    expanded:
      kind: "tag_node"
      description: "Named expanded extended-community-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named expanded extended-community-list"
      dependency: "policy-extended-community-list"
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
