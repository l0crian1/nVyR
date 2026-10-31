ipv6:
  kind: tag_node
  anchor: true
  description: IPv6 connection tracking timeout policy
  dependency: firewall-timeout-group-ipv6
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Timeout group name
  children:

    include_schema:
    - file: firewall/timeout-options.yaml.i
      as: null
