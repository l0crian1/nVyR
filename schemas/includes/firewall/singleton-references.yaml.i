children: # singleton group references

  inbound-interface-group:
    kind: leaf_node
    depends: firewall-interface-group
    description: Match inbound interface using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing interface-group name
    suggestors:
      config-path: {path: 'firewall group interface-group'}

  outbound-interface-group:
    kind: leaf_node
    depends: firewall-interface-group
    description: Match outbound interface using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing interface-group name
    suggestors:
      config-path: {path: 'firewall group interface-group'}

  source-mac-group:
    kind: leaf_node
    depends: firewall-mac-group
    description: Match source MAC using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing mac-group name
    suggestors:
      config-path: {path: 'firewall group mac-group'}

  destination-mac-group:
    kind: leaf_node
    depends: firewall-mac-group
    description: Match destination MAC using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing mac-group name
    suggestors:
      config-path: {path: 'firewall group mac-group'}

  source-port-group:
    kind: leaf_node
    depends: firewall-port-group
    description: Match source port using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing port-group name
    suggestors:
      config-path: {path: 'firewall group port-group'}

  destination-port-group:
    kind: leaf_node
    depends: firewall-port-group
    description: Match destination port using a named group
    validators:
      regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
    hints:
      name: Existing port-group name
    suggestors:
      config-path: {path: 'firewall group port-group'}
