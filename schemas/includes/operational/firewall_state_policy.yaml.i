state-policy:
  kind: node
  description: Installed connection-state policies and counters
  command: ['firewall.nvyr.op', 'show', '--section', 'state-policy']
  children: # state-policy

    include_schema:
    - file: operational/firewall_detail.yaml.i
      add:
        /command: ['firewall.nvyr.op', 'show', '--section', 'state-policy', '--detail']

    input:
      kind: node
      description: Input connection-state policy
      command: ['firewall.nvyr.op', 'show', '--section', 'state-policy', '--hook', 'input']
      children: # input

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'state-policy', '--hook', 'input', '--detail']

    forward:
      kind: node
      description: Forward connection-state policy
      command: ['firewall.nvyr.op', 'show', '--section', 'state-policy', '--hook', 'forward']
      children: # forward

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'state-policy', '--hook', 'forward', '--detail']

    output:
      kind: node
      description: Output connection-state policy
      command: ['firewall.nvyr.op', 'show', '--section', 'state-policy', '--hook', 'output']
      children: # output

        include_schema:
        - file: operational/firewall_detail.yaml.i
          add:
            /command: ['firewall.nvyr.op', 'show', '--section', 'state-policy', '--hook', 'output', '--detail']
