name:
  kind: tag_node
  dependency: firewall-chain-ipv6
  description: Named IPv6 firewall chain
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Chain name (1-63 letters, digits, underscores or hyphens; starts with a letter or underscore)
  children: # name

    include_schema:
    - file: firewall/defaults.yaml.i
      as: null
    - file: firewall/rule_ipv6.yaml.i
      add:
        /children/vlan:
          include_schema:
          - file: firewall/vlan.yaml.i
            as: null
