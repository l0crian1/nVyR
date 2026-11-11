isis:
  kind: node
  description: IS-IS routing state
  command:
  - 'isis.nvyr.op'
  - 'show'
  - '@line'
  children:

    summary:
      kind: node
      description: IS-IS summary
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children:

        json:
          kind: node
          description: Native JSON output
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children: {}

    neighbor:
      kind: node
      description: IS-IS neighbors
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children:

        detail:
          kind: node
          description: Detailed is-is neighbors
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        name:
          kind: tag_node
          description: Select system-id
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}
          positional: true
          validators:
            regex:
              pattern: '[A-Za-z0-9_.-]{1,128}'
          hints:
            system-id: Select system-id

        json:
          kind: node
          description: Native JSON output
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children: {}

    interface:
      kind: node
      description: IS-IS interfaces
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children:

        detail:
          kind: node
          description: Detailed is-is interfaces
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        name:
          kind: tag_node
          description: Select interface
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}
          positional: true
          validators:
            regex:
              pattern: '[A-Za-z_][A-Za-z0-9_.:-]{0,14}'
          hints:
            interface: Select interface

        json:
          kind: node
          description: Native JSON output
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children: {}

    database:
      kind: node
      description: Link-state database
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children:

        detail:
          kind: node
          description: Detailed link-state database
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

            name:
              kind: tag_node
              description: Select LSP
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}
              positional: true
              validators:
                regex:
                  pattern: '[A-Za-z0-9_.-]{1,128}'
              hints:
                lsp-id: Select LSP

        name:
          kind: tag_node
          description: Select lsp-id
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}
          positional: true
          validators:
            regex:
              pattern: '[A-Za-z0-9_.-]{1,128}'
          hints:
            lsp-id: Select lsp-id

        json:
          kind: node
          description: Native JSON output
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children: {}

    hostname:
      kind: node
      description: Learned system hostnames
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children: {}

    topology:
      kind: node
      description: SPF topology
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children:

        level:
          kind: tag_node
          description: Select a routing level
          choices:
            level-1: Level 1
            level-2: Level 2
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        json:
          kind: node
          description: Native JSON output
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children: {}

    route:
      kind: node
      description: IS-IS calculated routes
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children:

        level:
          kind: tag_node
          description: Select a routing level
          choices:
            level-1: Level 1
            level-2: Level 2
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

            backup:
              kind: node
              description: Backup routes
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}

        backup:
          kind: node
          description: Backup routes
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        json:
          kind: node
          description: Native JSON output
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children: {}

    fast-reroute:
      kind: node
      description: Local protection coverage
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children:

        summary:
          kind: node
          description: LFA coverage summary
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            level:
              kind: tag_node
              description: Select a routing level
              choices:
                level-1: Level 1
                level-2: Level 2
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'

    spf-delay:
      kind: node
      description: IETF SPF backoff state
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children: {}

    vrf:
      kind: tag_node
      description: Routing instance
      command:
      - 'isis.nvyr.op'
      - 'show'
      - '@line'
      children:

        summary:
          kind: node
          description: IS-IS summary
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        neighbor:
          kind: node
          description: IS-IS neighbors
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            detail:
              kind: node
              description: Detailed is-is neighbors
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}

            name:
              kind: tag_node
              description: Select system-id
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}
              positional: true
              validators:
                regex:
                  pattern: '[A-Za-z0-9_.-]{1,128}'
              hints:
                system-id: Select system-id

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        interface:
          kind: node
          description: IS-IS interfaces
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            detail:
              kind: node
              description: Detailed is-is interfaces
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}

            name:
              kind: tag_node
              description: Select interface
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}
              positional: true
              validators:
                regex:
                  pattern: '[A-Za-z_][A-Za-z0-9_.:-]{0,14}'
              hints:
                interface: Select interface

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        database:
          kind: node
          description: Link-state database
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            detail:
              kind: node
              description: Detailed link-state database
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}

                name:
                  kind: tag_node
                  description: Select LSP
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children:

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                      - 'isis.nvyr.op'
                      - 'show'
                      - '@line'
                      children: {}
                  positional: true
                  validators:
                    regex:
                      pattern: '[A-Za-z0-9_.-]{1,128}'
                  hints:
                    lsp-id: Select LSP

            name:
              kind: tag_node
              description: Select lsp-id
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}
              positional: true
              validators:
                regex:
                  pattern: '[A-Za-z0-9_.-]{1,128}'
              hints:
                lsp-id: Select lsp-id

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        hostname:
          kind: node
          description: Learned system hostnames
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children: {}

        topology:
          kind: node
          description: SPF topology
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            level:
              kind: tag_node
              description: Select a routing level
              choices:
                level-1: Level 1
                level-2: Level 2
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        route:
          kind: node
          description: IS-IS calculated routes
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            level:
              kind: tag_node
              description: Select a routing level
              choices:
                level-1: Level 1
                level-2: Level 2
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}

                backup:
                  kind: node
                  description: Backup routes
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children:

                    json:
                      kind: node
                      description: Native JSON output
                      command:
                      - 'isis.nvyr.op'
                      - 'show'
                      - '@line'
                      children: {}

            backup:
              kind: node
              description: Backup routes
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'
                  children: {}

            json:
              kind: node
              description: Native JSON output
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children: {}

        fast-reroute:
          kind: node
          description: Local protection coverage
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children:

            summary:
              kind: node
              description: LFA coverage summary
              command:
              - 'isis.nvyr.op'
              - 'show'
              - '@line'
              children:

                level:
                  kind: tag_node
                  description: Select a routing level
                  choices:
                    level-1: Level 1
                    level-2: Level 2
                  command:
                  - 'isis.nvyr.op'
                  - 'show'
                  - '@line'

        spf-delay:
          kind: node
          description: IETF SPF backoff state
          command:
          - 'isis.nvyr.op'
          - 'show'
          - '@line'
          children: {}
      validators:
        regex:
          pattern: '[A-Za-z][A-Za-z0-9_.-]{0,14}'
      hints:
        vrf: Routing instance
      choices:
        default: Default routing instance
        all: All routing instances
      suggestors:
        config-path:
          path: vrf name
