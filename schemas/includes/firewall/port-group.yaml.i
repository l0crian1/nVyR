port-group:
  kind: tag_node
  anchor: true
  dependency: firewall-port-group
  description: Named transport port group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Group name
  children: # port-group

    include_schema:
    - file: firewall/group-description.yaml.i
    - file: nftables/counter.yaml.i
    - file: nftables/last-used.yaml.i

    port:
      kind: leaf_node
      multi: true
      description: Transport port or inclusive range
      validators:
        port: {allow_range: true}
      hints:
        1-65535: Port number
        start-end: Inclusive port range

    include-group:
      kind: leaf_node
      multi: true
      description: Include configured members of another group of the same type
      depends: firewall-port-group
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing port-group name
      suggestors:
        config-path: {path: 'firewall group port-group'}
