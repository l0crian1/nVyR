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
        children:

          detail:
            kind: node
            description: Detailed neighbor state
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
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

      self-originate:
        kind: node
        description: Locally originated LSAs
        command:
        - "ospf.nvyr.op"
        - "show"
        - "@line"

      max-age:
        kind: node
        description: LSAs awaiting MaxAge removal
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
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originate:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              adv-router:
                kind: tag_node
                description: Advertising router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Advertising router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true

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
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originate:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              adv-router:
                kind: tag_node
                description: Advertising router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Advertising router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true

      summary:
        kind: node
        description: Summary LSAs
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
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originate:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              adv-router:
                kind: tag_node
                description: Advertising router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Advertising router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true

      asbr-summary:
        kind: node
        description: Asbr summary LSAs
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
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originate:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              adv-router:
                kind: tag_node
                description: Advertising router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Advertising router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true

      external:
        kind: node
        description: External LSAs
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
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originate:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              adv-router:
                kind: tag_node
                description: Advertising router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Advertising router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true

      nssa-external:
        kind: node
        description: Nssa external LSAs
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
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originate:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              adv-router:
                kind: tag_node
                description: Advertising router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Advertising router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true

      opaque-link:
        kind: node
        description: Opaque link LSAs
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
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originate:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              adv-router:
                kind: tag_node
                description: Advertising router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Advertising router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true

      opaque-area:
        kind: node
        description: Opaque area LSAs
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
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originate:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              adv-router:
                kind: tag_node
                description: Advertising router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Advertising router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true

      opaque-as:
        kind: node
        description: Opaque as LSAs
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
            children: {}
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          self-originate:
            kind: node
            description: Locally originated LSAs
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"

          id:
            kind: tag_node
            description: Link-state identifier
            validators:
              ipv4-address: {}
            hints:
              link-state-id: Link-state identifier
            children:

              adv-router:
                kind: tag_node
                description: Advertising router ID
                validators:
                  ipv4-address: {}
                hints:
                  router-id: Advertising router ID
                children: {}
                command:
                - "ospf.nvyr.op"
                - "show"
                - "@line"
            command:
            - "ospf.nvyr.op"
            - "show"
            - "@line"
            positional: true

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

  reachable-routers:
    kind: node
    description: Reachable routers in the OSPF topology
    command:
    - "ospf.nvyr.op"
    - "show"
    - "@line"
