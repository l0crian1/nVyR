group:
  kind: node
  description: Refresh imported firewall group membership
  children:

    address-group:
      kind: node
      description: Refresh address-group
      children:

        ipv4:
          kind: tag_node
          description: Refresh address-group attachments
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "address-group", "--family", "ipv4", "--name", "@6"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured group name
          suggestors:
            config-path: {path: 'firewall group address-group ipv4'}
          children:

            from-list:
              kind: tag_node
              description: Refresh one named attachment
              unattended: true
              stream: true
              command: ["firewall_lists.nvyr.op", "update", "address-group", "--family", "ipv4", "--name", "@6", "--attachment", "@8"]
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              hints:
                name: Attachment name

        ipv6:
          kind: tag_node
          description: Refresh address-group attachments
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "address-group", "--family", "ipv6", "--name", "@6"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured group name
          suggestors:
            config-path: {path: 'firewall group address-group ipv6'}
          children:

            from-list:
              kind: tag_node
              description: Refresh one named attachment
              unattended: true
              stream: true
              command: ["firewall_lists.nvyr.op", "update", "address-group", "--family", "ipv6", "--name", "@6", "--attachment", "@8"]
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              hints:
                name: Attachment name

    interface-group:
      kind: tag_node
      description: Refresh interface-group attachments
      unattended: true
      stream: true
      command: ["firewall_lists.nvyr.op", "update", "interface-group", "--family", "", "--name", "@5"]
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Configured group name
      suggestors:
        config-path: {path: 'firewall group interface-group'}
      children:

        from-list:
          kind: tag_node
          description: Refresh one named attachment
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "interface-group", "--family", "", "--name", "@5", "--attachment", "@7"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Attachment name

    mac-group:
      kind: tag_node
      description: Refresh mac-group attachments
      unattended: true
      stream: true
      command: ["firewall_lists.nvyr.op", "update", "mac-group", "--family", "", "--name", "@5"]
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Configured group name
      suggestors:
        config-path: {path: 'firewall group mac-group'}
      children:

        from-list:
          kind: tag_node
          description: Refresh one named attachment
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "mac-group", "--family", "", "--name", "@5", "--attachment", "@7"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Attachment name

    port-group:
      kind: tag_node
      description: Refresh port-group attachments
      unattended: true
      stream: true
      command: ["firewall_lists.nvyr.op", "update", "port-group", "--family", "", "--name", "@5"]
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Configured group name
      suggestors:
        config-path: {path: 'firewall group port-group'}
      children:

        from-list:
          kind: tag_node
          description: Refresh one named attachment
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "port-group", "--family", "", "--name", "@5", "--attachment", "@7"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Attachment name

    match-group:
      kind: node
      description: Refresh match-group
      children:

        ipv4:
          kind: tag_node
          description: Refresh match-group attachments
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "match-group", "--family", "ipv4", "--name", "@6"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured group name
          suggestors:
            config-path: {path: 'firewall group match-group ipv4'}
          children:

            from-csv:
              kind: tag_node
              description: Refresh one named attachment
              unattended: true
              stream: true
              command: ["firewall_lists.nvyr.op", "update", "match-group", "--family", "ipv4", "--name", "@6", "--attachment", "@8"]
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              hints:
                name: Attachment name

        ipv6:
          kind: tag_node
          description: Refresh match-group attachments
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "match-group", "--family", "ipv6", "--name", "@6"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured group name
          suggestors:
            config-path: {path: 'firewall group match-group ipv6'}
          children:

            from-csv:
              kind: tag_node
              description: Refresh one named attachment
              unattended: true
              stream: true
              command: ["firewall_lists.nvyr.op", "update", "match-group", "--family", "ipv6", "--name", "@6", "--attachment", "@8"]
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              hints:
                name: Attachment name

        inet:
          kind: tag_node
          description: Refresh match-group attachments
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "match-group", "--family", "inet", "--name", "@6"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured group name
          suggestors:
            config-path: {path: 'firewall group match-group inet'}
          children:

            from-csv:
              kind: tag_node
              description: Refresh one named attachment
              unattended: true
              stream: true
              command: ["firewall_lists.nvyr.op", "update", "match-group", "--family", "inet", "--name", "@6", "--attachment", "@8"]
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              hints:
                name: Attachment name

    map:
      kind: node
      description: Refresh map
      children:

        ipv4:
          kind: tag_node
          description: Refresh map attachments
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "map", "--family", "ipv4", "--name", "@6"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured group name
          suggestors:
            config-path: {path: 'firewall group map ipv4'}
          children:

            from-csv:
              kind: tag_node
              description: Refresh one named attachment
              unattended: true
              stream: true
              command: ["firewall_lists.nvyr.op", "update", "map", "--family", "ipv4", "--name", "@6", "--attachment", "@8"]
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              hints:
                name: Attachment name

        ipv6:
          kind: tag_node
          description: Refresh map attachments
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "map", "--family", "ipv6", "--name", "@6"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured group name
          suggestors:
            config-path: {path: 'firewall group map ipv6'}
          children:

            from-csv:
              kind: tag_node
              description: Refresh one named attachment
              unattended: true
              stream: true
              command: ["firewall_lists.nvyr.op", "update", "map", "--family", "ipv6", "--name", "@6", "--attachment", "@8"]
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              hints:
                name: Attachment name

        inet:
          kind: tag_node
          description: Refresh map attachments
          unattended: true
          stream: true
          command: ["firewall_lists.nvyr.op", "update", "map", "--family", "inet", "--name", "@6"]
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured group name
          suggestors:
            config-path: {path: 'firewall group map inet'}
          children:

            from-csv:
              kind: tag_node
              description: Refresh one named attachment
              unattended: true
              stream: true
              command: ["firewall_lists.nvyr.op", "update", "map", "--family", "inet", "--name", "@6", "--attachment", "@8"]
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              hints:
                name: Attachment name
