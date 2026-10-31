ipv4:
  kind: node
  description: IPv4 firewall rules and groups
  command: ['firewall.nvyr.op', 'show', '--family', 'ipv4']
  children: # ipv4

    include_schema:
    - file: operational/firewall_detail.yaml.i
      add:
        /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--detail']

    input:
      kind: node
      description: Input firewall rules
      command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'input']
      children: # input

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'input', '--detail']

        filter:
          kind: node
          description: Installed filter rules
          command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'input', '--stage', 'filter']
          children: # filter

            limits:
              kind: node
              description: Installed rule limits and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'input', '--stage', 'filter']

            quotas:
              kind: node
              description: Installed rule quotas and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'input', '--stage', 'filter']

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'input', '--stage', 'filter', '--detail']
            - file: operational/firewall_rule.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'input', '--stage', 'filter', '--rule', '@7']
                /children/limit/command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'input', '--stage', 'filter', '--rule', '@7']
                /children/quota/command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'input', '--stage', 'filter', '--rule', '@7']
                /children/detail/command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'input', '--stage', 'filter', '--rule', '@7', '--detail']
                /suggestors:
                  config-path: {path: 'firewall ipv4 input filter rule'}

    forward:
      kind: node
      description: Forward firewall rules
      command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'forward']
      children: # forward

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'forward', '--detail']

        filter:
          kind: node
          description: Installed filter rules
          command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'forward', '--stage', 'filter']
          children: # filter

            limits:
              kind: node
              description: Installed rule limits and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'forward', '--stage', 'filter']

            quotas:
              kind: node
              description: Installed rule quotas and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'forward', '--stage', 'filter']

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'forward', '--stage', 'filter', '--detail']
            - file: operational/firewall_rule.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'forward', '--stage', 'filter', '--rule', '@7']
                /children/limit/command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'forward', '--stage', 'filter', '--rule', '@7']
                /children/quota/command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'forward', '--stage', 'filter', '--rule', '@7']
                /children/detail/command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'forward', '--stage', 'filter', '--rule', '@7', '--detail']
                /suggestors:
                  config-path: {path: 'firewall ipv4 forward filter rule'}

    output:
      kind: node
      description: Output firewall rules
      command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output']
      children: # output

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output', '--detail']

        filter:
          kind: node
          description: Installed filter rules
          command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output', '--stage', 'filter']
          children: # filter

            limits:
              kind: node
              description: Installed rule limits and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'output', '--stage', 'filter']

            quotas:
              kind: node
              description: Installed rule quotas and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'output', '--stage', 'filter']

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output', '--stage', 'filter', '--detail']
            - file: operational/firewall_rule.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output', '--stage', 'filter', '--rule', '@7']
                /children/limit/command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'output', '--stage', 'filter', '--rule', '@7']
                /children/quota/command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'output', '--stage', 'filter', '--rule', '@7']
                /children/detail/command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output', '--stage', 'filter', '--rule', '@7', '--detail']
                /suggestors:
                  config-path: {path: 'firewall ipv4 output filter rule'}

        raw:
          kind: node
          description: Installed raw rules
          command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output', '--stage', 'raw']
          children: # raw

            limits:
              kind: node
              description: Installed rule limits and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'output', '--stage', 'raw']

            quotas:
              kind: node
              description: Installed rule quotas and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'output', '--stage', 'raw']

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output', '--stage', 'raw', '--detail']
            - file: operational/firewall_rule.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output', '--stage', 'raw', '--rule', '@7']
                /children/limit/command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'output', '--stage', 'raw', '--rule', '@7']
                /children/quota/command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'output', '--stage', 'raw', '--rule', '@7']
                /children/detail/command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'output', '--stage', 'raw', '--rule', '@7', '--detail']
                /suggestors:
                  config-path: {path: 'firewall ipv4 output raw rule'}

    prerouting:
      kind: node
      description: Prerouting firewall rules
      command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'prerouting']
      children: # prerouting

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'prerouting', '--detail']

        raw:
          kind: node
          description: Installed raw rules
          command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'prerouting', '--stage', 'raw']
          children: # raw

            limits:
              kind: node
              description: Installed rule limits and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'prerouting', '--stage', 'raw']

            quotas:
              kind: node
              description: Installed rule quotas and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'prerouting', '--stage', 'raw']

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'prerouting', '--stage', 'raw', '--detail']
            - file: operational/firewall_rule.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'prerouting', '--stage', 'raw', '--rule', '@7']
                /children/limit/command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'prerouting', '--stage', 'raw', '--rule', '@7']
                /children/quota/command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'prerouting', '--stage', 'raw', '--rule', '@7']
                /children/detail/command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'prerouting', '--stage', 'raw', '--rule', '@7', '--detail']
                /suggestors:
                  config-path: {path: 'firewall ipv4 prerouting raw rule'}

    name:
      kind: tag_node
      optional_value: true
      description: Named firewall chains
      command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--named', '--chain_name', '@5']
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Named firewall chain in this address family
      suggestors:
        config-path: {path: 'firewall ipv4 name'}
      children: # name

        limits:
          kind: node
          description: Installed rule limits and runtime state
          command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--named', '--chain_name', '@5']

        quotas:
          kind: node
          description: Installed rule quotas and runtime state
          command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--named', '--chain_name', '@5']

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--named', '--chain_name', '@5', '--detail']
        - file: operational/firewall_rule.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--named', '--chain_name', '@5', '--rule', '@7']
            /children/limit/command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--named', '--chain_name', '@5', '--rule', '@7']
            /children/quota/command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--named', '--chain_name', '@5', '--rule', '@7']
            /children/detail/command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--named', '--chain_name', '@5', '--rule', '@7', '--detail']

    ingress:
      kind: node
      description: Ingress firewall rules
      command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'ingress']
      children: # ingress

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'ingress', '--detail']

        filter:
          kind: node
          description: Installed filter rules
          command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'ingress', '--stage', 'filter']
          children: # filter

            limits:
              kind: node
              description: Installed rule limits and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'ingress', '--stage', 'filter']

            quotas:
              kind: node
              description: Installed rule quotas and runtime state
              command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'ingress', '--stage', 'filter']

            include_schema:
            - file: operational/firewall_detail.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'ingress', '--stage', 'filter', '--detail']
            - file: operational/firewall_rule.yaml.i
              add:
                /command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'ingress', '--stage', 'filter', '--rule', '@7']
                /children/limit/command: ['firewall.nvyr.op', 'runtime', 'limit', '--family', 'ipv4', '--hook', 'ingress', '--stage', 'filter', '--rule', '@7']
                /children/quota/command: ['firewall.nvyr.op', 'runtime', 'quota', '--family', 'ipv4', '--hook', 'ingress', '--stage', 'filter', '--rule', '@7']
                /children/detail/command: ['firewall.nvyr.op', 'show', '--family', 'ipv4', '--hook', 'ingress', '--stage', 'filter', '--rule', '@7', '--detail']
                /suggestors:
                  config-path: {path: 'firewall ipv4 ingress filter rule'}
