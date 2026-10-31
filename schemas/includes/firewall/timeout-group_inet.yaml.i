inet:
  kind: tag_node
  anchor: true
  description: IPv4 and IPv6 connection tracking timeout policy
  dependency: firewall-timeout-group-inet
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Timeout group name
  children:

    include_schema:
    - file: firewall/timeout-options.yaml.i
      as: null
