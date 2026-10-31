name:
  kind: tag_node
  dependency: firewall-chain-ipv4
  description: Named IPv4 firewall chain
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Chain name (1-63 letters, digits, underscores or hyphens; starts with a letter or underscore)
  children: # name

    include_schema:
    - file: firewall/defaults.yaml.i
      as: null
    - file: firewall/rule.yaml.i
      add:
        /children/vlan:
          include_schema:
          - file: firewall/vlan.yaml.i
            as: null
