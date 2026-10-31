children: # singleton group references

  include_schema:
  - file: firewall/singleton-references.yaml.i
    as: null

  source-address-group:
    kind: leaf_node
    depends: firewall-address-group-ipv6
    description: Match source address using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing address-group IPv6 name
    suggestors:
      config-path: {path: 'firewall group address-group ipv6'}

  destination-address-group:
    kind: leaf_node
    depends: firewall-address-group-ipv6
    description: Match destination address using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing address-group IPv6 name
    suggestors:
      config-path: {path: 'firewall group address-group ipv6'}

  source-domain-group:
    kind: leaf_node
    depends: firewall-domain-group-ipv6
    description: Match source address using a DNS-populated group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing domain-group IPv6 name
    suggestors:
      config-path: {path: 'firewall group domain-group ipv6'}

  destination-domain-group:
    kind: leaf_node
    depends: firewall-domain-group-ipv6
    description: Match destination address using a DNS-populated group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing domain-group IPv6 name
    suggestors:
      config-path: {path: 'firewall group domain-group ipv6'}
