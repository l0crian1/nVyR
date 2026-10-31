children:

  ipv4-policy:
    kind: leaf_node
    depends: firewall-chain-ipv4
    description: Named IPv4 policy chain
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing IPv4 named chain
    suggestors:
      config-path: {path: 'firewall ipv4 name'}

  ipv6-policy:
    kind: leaf_node
    depends: firewall-chain-ipv6
    description: Named IPv6 policy chain
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing IPv6 named chain
    suggestors:
      config-path: {path: 'firewall ipv6 name'}
