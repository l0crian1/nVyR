children: # singleton group references

  include_schema:
  - file: firewall/singleton-references.yaml.i
    as: null

  source-address-group:
    kind: leaf_node
    depends: firewall-address-group-ipv4
    description: Match source address using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing address-group IPv4 name
    suggestors:
      config-path: {path: 'firewall group address-group ipv4'}

  destination-address-group:
    kind: leaf_node
    depends: firewall-address-group-ipv4
    description: Match destination address using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing address-group IPv4 name
    suggestors:
      config-path: {path: 'firewall group address-group ipv4'}

  source-domain-group:
    kind: leaf_node
    depends: firewall-domain-group-ipv4
    description: Match source address using a DNS-populated group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing domain-group IPv4 name
    suggestors:
      config-path: {path: 'firewall group domain-group ipv4'}

  destination-domain-group:
    kind: leaf_node
    depends: firewall-domain-group-ipv4
    description: Match destination address using a DNS-populated group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing domain-group IPv4 name
    suggestors:
      config-path: {path: 'firewall group domain-group ipv4'}
