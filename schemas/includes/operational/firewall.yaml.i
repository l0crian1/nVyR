firewall:
  kind: node
  description: Installed firewall rules, groups, and flowtables
  command: ['firewall.nvyr.op', 'show']
  children: # firewall

    fail-safe:
      kind: node
      description: Installed early firewall protection, when active
      command: ['firewall.nvyr.op', 'show', '--failsafe']
      children:

        detail:
          kind: leaf_node
          valueless: true
          description: Detailed early firewall rules and groups
          command: ['firewall.nvyr.op', 'show', '--failsafe', '--detail']

    domain-group:
      kind: node
      description: DNS-backed firewall group lookups
      command: ['domain_groups.nvyr.op', 'show']
      children:

        ipv4:
          kind: tag_node
          optional_value: true
          description: IPv4 domain groups, optionally filtered by name
          command: ['domain_groups.nvyr.op', 'show', '--family', 'ipv4', '--name', '@5']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          suggestors:
            config-path: {path: 'firewall group domain-group ipv4'}
          hints:
            name: Domain group name

        ipv6:
          kind: tag_node
          optional_value: true
          description: IPv6 domain groups, optionally filtered by name
          command: ['domain_groups.nvyr.op', 'show', '--family', 'ipv6', '--name', '@5']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          suggestors:
            config-path: {path: 'firewall group domain-group ipv6'}
          hints:
            name: Domain group name

    geoip:
      kind: node
      description: DB-IP database version, update status and configured country groups
      command: ['geoip.nvyr.op', 'show']

    include_schema:
    - file: operational/firewall_trace_show.yaml.i
    - file: operational/firewall_detail.yaml.i
      add:
        /command: ['firewall.nvyr.op', 'show', '--detail']
    - file: operational/firewall_ipv4.yaml.i
    - file: operational/firewall_ipv6.yaml.i
    - file: operational/firewall_inet.yaml.i
    - file: operational/firewall_groups.yaml.i
    - file: operational/firewall_state_policy.yaml.i

    zone:
      kind: node
      description: Installed zone interface mappings and directional policies
      command: ['firewall.nvyr.op', 'show', '--section', 'zone']
      children:

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'zone', '--detail']

        ipv4:
          kind: tag_node
          optional_value: true
          description: IPv4 zone policies, optionally scoped to a source zone
          command: ['firewall.nvyr.op', 'show', '--section', 'zone', '--family', 'ipv4', '--zone_name', '@5']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Source zone name
          suggestors:
            config-path: {path: 'firewall zone'}
          children:

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'zone', '--family', 'ipv4', '--zone_name', '@5', '--detail']

        ipv6:
          kind: tag_node
          optional_value: true
          description: IPv6 zone policies, optionally scoped to a source zone
          command: ['firewall.nvyr.op', 'show', '--section', 'zone', '--family', 'ipv6', '--zone_name', '@5']
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Source zone name
          suggestors:
            config-path: {path: 'firewall zone'}
          children:

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--section', 'zone', '--family', 'ipv6', '--zone_name', '@5', '--detail']

    flowtable:
      kind: tag_node
      optional_value: true
      description: Installed flowtables
      command: ['firewall.nvyr.op', 'show', '--section', 'flowtable', '--group_name', '@4']
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Configured flowtable name
      suggestors:
        config-path: {path: 'firewall flowtable'}
      children: # flowtable

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'flowtable', '--group_name', '@4', '--detail']
