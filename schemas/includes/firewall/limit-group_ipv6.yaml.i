ipv6:
  kind: tag_node
  anchor: true
  description: Shared IPv6 rate allowance
  dependency: firewall-limit-group-ipv6
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Limit group name
  children: # ipv6 limit group

    include_schema:
    - file: firewall/limit-options.yaml.i
      as: null
    - file: firewall/group-description.yaml.i
