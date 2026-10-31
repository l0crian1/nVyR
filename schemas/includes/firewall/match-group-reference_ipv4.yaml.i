match-group:
  kind: leaf_node
  depends: firewall-match-group-ipv4
  description: Match-group supplying additional packet matches
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Existing IPv4 match-group
  suggestors:
    config-path: {path: 'firewall group match-group ipv4'}
