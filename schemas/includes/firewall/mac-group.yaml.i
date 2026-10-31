mac-group:
  kind: tag_node
  anchor: true
  dependency: firewall-mac-group
  description: Named MAC address group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Group name
  children: # mac-group

    include_schema:
    - file: firewall/group-description.yaml.i
    - file: nftables/counter.yaml.i
    - file: nftables/last-used.yaml.i

    address:
      kind: leaf_node
      multi: true
      description: MAC address
      strip_kind: mac
      validators:
        mac: {unicast: false}
      hints:
        xx:xx:xx:xx:xx:xx: Ethernet address

    include-group:
      kind: leaf_node
      multi: true
      description: Include configured members of another group of the same type
      depends: firewall-mac-group
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing mac-group name
      suggestors:
        config-path: {path: 'firewall group mac-group'}
