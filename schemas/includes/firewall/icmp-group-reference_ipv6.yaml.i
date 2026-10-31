icmp-group:
  kind: leaf_node
  negatable: true
  depends: firewall-icmp-group-ipv6
  description: Match ICMP types or type/code pairs using a named group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Existing IPv6 ICMP group
  suggestors:
    config-path: {path: 'firewall group icmp-group ipv6'}
