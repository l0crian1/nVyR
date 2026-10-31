group:
  kind: node
  description: Installed firewall sets and maps
  command: ['firewall.nvyr.op', 'show', '--section', 'group']
  children: # group

    quota-group:
      kind: tag_node
      optional_value: true
      description: Shared byte quotas and current consumption
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'quota-group', '--group_name', '@5']
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Quota group name
      suggestors:
        config-path: {path: 'firewall group quota-group'}
      children: # quota-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'quota-group', '--group_name', '@5', '--detail']

    include_schema:
    - file: operational/firewall_detail.yaml.i
      add:
        /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--detail']

    map:
      kind: node
      description: Installed map objects
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'map']
      children: # map

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'map', '--detail']

        ipv4:
          kind: tag_node
          optional_value: true
          description: IPv4 map entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'map', '--family', 'ipv4', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured map name in this address family
          suggestors:
            config-path: {path: 'firewall group map ipv4'}
          children: # ipv4

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'map', '--family', 'ipv4', '--group_name', '@6', '--detail']

        inet:
          kind: tag_node
          optional_value: true
          description: Family-neutral map entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'map', '--family', 'inet', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured map name in this address family
          suggestors:
            config-path: {path: 'firewall group map inet'}
          children: # inet

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'map', '--family', 'inet', '--group_name', '@6', '--detail']

        ipv6:
          kind: tag_node
          optional_value: true
          description: IPv6 map entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'map', '--family', 'ipv6', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured map name in this address family
          suggestors:
            config-path: {path: 'firewall group map ipv6'}
          children: # ipv6

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'map', '--family', 'ipv6', '--group_name', '@6', '--detail']

    match-group:
      kind: node
      description: Installed match-group objects
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'match-group']
      children: # match-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'match-group', '--detail']

        ipv4:
          kind: tag_node
          optional_value: true
          description: IPv4 match-group entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'match-group', '--family', 'ipv4', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured match-group name in this address family
          suggestors:
            config-path: {path: 'firewall group match-group ipv4'}
          children: # ipv4

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'match-group', '--family', 'ipv4', '--group_name', '@6', '--detail']

        inet:
          kind: tag_node
          optional_value: true
          description: Family-neutral match-group entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'match-group', '--family', 'inet', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured match-group name in this address family
          suggestors:
            config-path: {path: 'firewall group match-group inet'}
          children: # inet

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'match-group', '--family', 'inet', '--group_name', '@6', '--detail']

        ipv6:
          kind: tag_node
          optional_value: true
          description: IPv6 match-group entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'match-group', '--family', 'ipv6', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured match-group name in this address family
          suggestors:
            config-path: {path: 'firewall group match-group ipv6'}
          children: # ipv6

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'match-group', '--family', 'ipv6', '--group_name', '@6', '--detail']

    address-group:
      kind: node
      description: Installed address-group objects
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'address-group']
      children: # address-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'address-group', '--detail']

        ipv4:
          kind: tag_node
          optional_value: true
          description: IPv4 address-group entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'address-group', '--family', 'ipv4', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured address-group name in this address family
          suggestors:
            config-path: {path: 'firewall group address-group ipv4'}
          children: # ipv4

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'address-group', '--family', 'ipv4', '--group_name', '@6', '--detail']

        ipv6:
          kind: tag_node
          optional_value: true
          description: IPv6 address-group entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'address-group', '--family', 'ipv6', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured address-group name in this address family
          suggestors:
            config-path: {path: 'firewall group address-group ipv6'}
          children: # ipv6

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'address-group', '--family', 'ipv6', '--group_name', '@6', '--detail']

    icmp-group:
      kind: node
      description: Installed icmp-group objects
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'icmp-group']
      children: # icmp-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'icmp-group', '--detail']

        ipv4:
          kind: tag_node
          optional_value: true
          description: IPv4 icmp-group types and codes
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'icmp-group', '--family', 'ipv4', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured icmp-group name in this address family
          suggestors:
            config-path: {path: 'firewall group icmp-group ipv4'}
          children: # ipv4

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'icmp-group', '--family', 'ipv4', '--group_name', '@6', '--detail']

        ipv6:
          kind: tag_node
          optional_value: true
          description: IPv6 icmp-group types and codes
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'icmp-group', '--family', 'ipv6', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured icmp-group name in this address family
          suggestors:
            config-path: {path: 'firewall group icmp-group ipv6'}
          children: # ipv6

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'icmp-group', '--family', 'ipv6', '--group_name', '@6', '--detail']

    domain-group:
      kind: node
      description: Installed domain-group objects
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'domain-group']
      children: # domain-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'domain-group', '--detail']

        ipv4:
          kind: tag_node
          optional_value: true
          description: IPv4 domain-group entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'domain-group', '--family', 'ipv4', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured domain-group name in this address family
          suggestors:
            config-path: {path: 'firewall group domain-group ipv4'}
          children: # ipv4

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'domain-group', '--family', 'ipv4', '--group_name', '@6', '--detail']

        ipv6:
          kind: tag_node
          optional_value: true
          description: IPv6 domain-group entries
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'domain-group', '--family', 'ipv6', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured domain-group name in this address family
          suggestors:
            config-path: {path: 'firewall group domain-group ipv6'}
          children: # ipv6

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'domain-group', '--family', 'ipv6', '--group_name', '@6', '--detail']

    interface-group:
      kind: tag_node
      optional_value: true
      description: Installed interface-group entries
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'interface-group', '--group_name', '@5']
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Configured interface-group name
      suggestors:
        config-path: {path: 'firewall group interface-group'}
      children: # interface-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'interface-group', '--group_name', '@5', '--detail']

    mac-group:
      kind: tag_node
      optional_value: true
      description: Installed mac-group entries
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'mac-group', '--group_name', '@5']
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Configured mac-group name
      suggestors:
        config-path: {path: 'firewall group mac-group'}
      children: # mac-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'mac-group', '--group_name', '@5', '--detail']

    port-group:
      kind: tag_node
      optional_value: true
      description: Installed port-group entries
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'port-group', '--group_name', '@5']
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Configured port-group name
      suggestors:
        config-path: {path: 'firewall group port-group'}
      children: # port-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'port-group', '--group_name', '@5', '--detail']

    timeout-group:
      kind: node
      description: Installed timeout-group objects
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'timeout-group']
      children: # timeout-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'timeout-group', '--detail']

        ipv4:
          kind: tag_node
          optional_value: true
          description: IPv4 connection timeout policies
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'timeout-group', '--family', 'ipv4', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured timeout-group name in this address family
          suggestors:
            config-path: {path: 'firewall group timeout-group ipv4'}
          children: # ipv4

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'timeout-group', '--family', 'ipv4', '--group_name', '@6', '--detail']

        inet:
          kind: tag_node
          optional_value: true
          description: Family-neutral connection timeout policies
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'timeout-group', '--family', 'inet', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured timeout-group name in this address family
          suggestors:
            config-path: {path: 'firewall group timeout-group inet'}
          children: # inet

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'timeout-group', '--family', 'inet', '--group_name', '@6', '--detail']

        ipv6:
          kind: tag_node
          optional_value: true
          description: IPv6 connection timeout policies
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'timeout-group', '--family', 'ipv6', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured timeout-group name in this address family
          suggestors:
            config-path: {path: 'firewall group timeout-group ipv6'}
          children: # ipv6

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'timeout-group', '--family', 'ipv6', '--group_name', '@6', '--detail']


    limit-group:
      kind: node
      description: Installed limit-group objects
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'limit-group']
      children: # limit-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'limit-group', '--detail']

        ipv4:
          kind: tag_node
          optional_value: true
          description: IPv4 limit-group allowances
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'limit-group', '--family', 'ipv4', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured limit-group name in this address family
          suggestors:
            config-path: {path: 'firewall group limit-group ipv4'}
          children: # ipv4

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'limit-group', '--family', 'ipv4', '--group_name', '@6', '--detail']

        inet:
          kind: tag_node
          optional_value: true
          description: Family-neutral limit-group allowances
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'limit-group', '--family', 'inet', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured limit-group name in this address family
          suggestors:
            config-path: {path: 'firewall group limit-group inet'}
          children: # inet

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'limit-group', '--family', 'inet', '--group_name', '@6', '--detail']

        ipv6:
          kind: tag_node
          optional_value: true
          description: IPv6 limit-group allowances
          command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'limit-group', '--family', 'ipv6', '--group_name', '@6']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured limit-group name in this address family
          suggestors:
            config-path: {path: 'firewall group limit-group ipv6'}
          children: # ipv6

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'limit-group', '--family', 'ipv6', '--group_name', '@6', '--detail']


    counter-group:
      kind: tag_node
      optional_value: true
      description: Installed counter-group counts
      command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'counter-group', '--group_name', '@5']
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Configured counter-group name
      suggestors:
        config-path: {path: 'firewall group counter-group'}
      children: # counter-group

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'counter-group', '--group_name', '@5', '--detail']
