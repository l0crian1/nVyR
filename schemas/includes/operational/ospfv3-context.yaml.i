children:

  interface:
    kind: node
    description: OSPF interfaces
    command:
    - "ospf.nvyr.op"
    - "show"
    - "@line"
    children:

      name:
        kind: tag_node
        description: Select an interface
        validators:
          regex:
            pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
        hints:
          interface: Select an interface
        children: {}
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        positional: true
        suggestors:
          interfaces: {}

      traffic:
        kind: node
        description: OSPF packet counters
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          name:
            kind: tag_node
            description: Select an interface
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'
            hints:
              interface: Select an interface
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true
            suggestors:
              interfaces: {}

      prefix:
        kind: node
        description: Connected prefixes advertised by OSPFv3
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"

  neighbor:
    kind: node
    description: OSPF neighbors
    command:
    - "ospf.nvyr.op"
    - "show"
    - "@line"
    children:

      router-id:
        kind: tag_node
        description: Select a neighbor router ID
        validators:
          ipv4-address: {}
        hints:
          router-id: Select a neighbor router ID
        children: {}
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        positional: true

      detail:
        kind: node
        description: Detailed neighbor states
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"

      drchoice:
        kind: node
        description: Designated router election choices
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"

  database:
    kind: node
    description: Link-state database
    command:
    - "ospf.nvyr.op"
    - "show"
    - "@line"
    children:

      detail:
        kind: node
        description: Detailed link-state database
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"

      self-originated:
        kind: node
        description: Locally originated LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"

      router:
        kind: node
        description: Router LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          adv-router:
            kind: tag_node
            description: Advertising router ID
            validators:
              ipv4-address: {}
            hints:
              router-id: Advertising router ID
            children:

              linkstate-id:
                kind: tag_node
                description: Link-state identifier
                validators:
                  ipv4-address: {}
                hints:
                  link-state-id: Link-state identifier
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originated:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          detail:
            kind: node
            description: Detailed LSA contents
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          linkstate-id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              detail:
                kind: node
                description: Detailed LSA contents
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

      network:
        kind: node
        description: Network LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          adv-router:
            kind: tag_node
            description: Advertising router ID
            validators:
              ipv4-address: {}
            hints:
              router-id: Advertising router ID
            children:

              linkstate-id:
                kind: tag_node
                description: Link-state identifier
                validators:
                  ipv4-address: {}
                hints:
                  link-state-id: Link-state identifier
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originated:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          detail:
            kind: node
            description: Detailed LSA contents
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          linkstate-id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              detail:
                kind: node
                description: Detailed LSA contents
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

      inter-prefix:
        kind: node
        description: Inter prefix LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          adv-router:
            kind: tag_node
            description: Advertising router ID
            validators:
              ipv4-address: {}
            hints:
              router-id: Advertising router ID
            children:

              linkstate-id:
                kind: tag_node
                description: Link-state identifier
                validators:
                  ipv4-address: {}
                hints:
                  link-state-id: Link-state identifier
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originated:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          detail:
            kind: node
            description: Detailed LSA contents
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          linkstate-id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              detail:
                kind: node
                description: Detailed LSA contents
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

      inter-router:
        kind: node
        description: Inter router LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          adv-router:
            kind: tag_node
            description: Advertising router ID
            validators:
              ipv4-address: {}
            hints:
              router-id: Advertising router ID
            children:

              linkstate-id:
                kind: tag_node
                description: Link-state identifier
                validators:
                  ipv4-address: {}
                hints:
                  link-state-id: Link-state identifier
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originated:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          detail:
            kind: node
            description: Detailed LSA contents
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          linkstate-id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              detail:
                kind: node
                description: Detailed LSA contents
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

      as-external:
        kind: node
        description: As external LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          adv-router:
            kind: tag_node
            description: Advertising router ID
            validators:
              ipv4-address: {}
            hints:
              router-id: Advertising router ID
            children:

              linkstate-id:
                kind: tag_node
                description: Link-state identifier
                validators:
                  ipv4-address: {}
                hints:
                  link-state-id: Link-state identifier
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originated:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          detail:
            kind: node
            description: Detailed LSA contents
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          linkstate-id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              detail:
                kind: node
                description: Detailed LSA contents
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

      type-7:
        kind: node
        description: Type 7 LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          adv-router:
            kind: tag_node
            description: Advertising router ID
            validators:
              ipv4-address: {}
            hints:
              router-id: Advertising router ID
            children:

              linkstate-id:
                kind: tag_node
                description: Link-state identifier
                validators:
                  ipv4-address: {}
                hints:
                  link-state-id: Link-state identifier
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originated:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          detail:
            kind: node
            description: Detailed LSA contents
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          linkstate-id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              detail:
                kind: node
                description: Detailed LSA contents
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

      link:
        kind: node
        description: Link LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          adv-router:
            kind: tag_node
            description: Advertising router ID
            validators:
              ipv4-address: {}
            hints:
              router-id: Advertising router ID
            children:

              linkstate-id:
                kind: tag_node
                description: Link-state identifier
                validators:
                  ipv4-address: {}
                hints:
                  link-state-id: Link-state identifier
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originated:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          detail:
            kind: node
            description: Detailed LSA contents
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          linkstate-id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              detail:
                kind: node
                description: Detailed LSA contents
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

      intra-prefix:
        kind: node
        description: Intra prefix LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          adv-router:
            kind: tag_node
            description: Advertising router ID
            validators:
              ipv4-address: {}
            hints:
              router-id: Advertising router ID
            children:

              linkstate-id:
                kind: tag_node
                description: Link-state identifier
                validators:
                  ipv4-address: {}
                hints:
                  link-state-id: Link-state identifier
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originated:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          detail:
            kind: node
            description: Detailed LSA contents
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          linkstate-id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              detail:
                kind: node
                description: Detailed LSA contents
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

      group-membership:
        kind: node
        description: Group membership LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          adv-router:
            kind: tag_node
            description: Advertising router ID
            validators:
              ipv4-address: {}
            hints:
              router-id: Advertising router ID
            children:

              linkstate-id:
                kind: tag_node
                description: Link-state identifier
                validators:
                  ipv4-address: {}
                hints:
                  link-state-id: Link-state identifier
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originated:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          detail:
            kind: node
            description: Detailed LSA contents
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          linkstate-id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              detail:
                kind: node
                description: Detailed LSA contents
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

  route:
    kind: node
    description: OSPF route calculations
    command:
    - "ospf.nvyr.op"
    - "show"
    - "@line"
    children:

      detail:
        kind: node
        description: Detailed OSPF routes
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"

  border-routers:
    kind: node
    description: Area border and autonomous-system boundary routers
    command:
    - "ospf.nvyr.op"
    - "show"
    - "@line"

  summary-address:
    kind: node
    description: External route summaries
    command:
    - "ospf.nvyr.op"
    - "show"
    - "@line"
    children:

      detail:
        kind: node
        description: Detailed external summaries
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"

  graceful-restart:
    kind: node
    description: Graceful restart state
    children:

      helper:
        kind: node
        description: Graceful restart helper state
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
        children:

          detail:
            kind: node
            description: Detailed helper state
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

  spf:
    kind: node
    description: Shortest-path calculations
    children:

      tree:
        kind: node
        description: Shortest-path tree
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"
