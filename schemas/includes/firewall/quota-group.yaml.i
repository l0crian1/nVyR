quota-group:
  kind: tag_node
  anchor: true
  description: Shared cumulative byte allowance across IPv4 and IPv6 rules
  dependency: firewall-quota-group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Quota group name
  children: # quota-group

    include_schema:
    - file: firewall/quota-options.yaml.i
      as: null
    - file: firewall/group-description.yaml.i
