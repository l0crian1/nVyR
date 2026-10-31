group:
  kind: leaf_node
  description: Share the allowance owned by a named IPv6 limit group
  depends: firewall-limit-group-ipv6
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Limit group name
  suggestors:
    config-path: {path: 'firewall group limit-group ipv6'}
