large-community-list:
  kind: "node"
  description: "BGP large-community-lists"
  anchor: true
  children:

    standard:
      kind: "tag_node"
      description: "Named standard large-community-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named standard large-community-list"
      dependency: "policy-large-community-list"
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
                  large: true
                  modifiers: false
              hints:
                asn:value:value: "Community value to match"
              multi: true

    expanded:
      kind: "tag_node"
      description: "Named expanded large-community-list"
      anchor: true
      validators:
        regex:
          pattern: "[A-Za-z_][A-Za-z0-9_.-]{0,127}"
      hints:
        name: "Named expanded large-community-list"
      dependency: "policy-large-community-list"
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
