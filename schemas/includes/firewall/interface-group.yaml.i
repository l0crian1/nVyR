interface-group:
  kind: tag_node
  anchor: true
  dependency: firewall-interface-group
  description: Named interface group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Group name
  children: # interface-group

    include_schema:
    - file: firewall/group-description.yaml.i
    - file: nftables/counter.yaml.i
    - file: nftables/last-used.yaml.i

    vrf:
      kind: leaf_node
      valueless: true
      description: Members are VRF-owned interfaces; match slave interface names in INPUT

    interface:
      kind: leaf_node
      multi: true
      description: Interface name or prefix ending in *
      depends: interface
      validators:
        interface-match: {}
      hints:
        name: Interface name
        prefix*: Include interface names starting with this prefix
      suggestors:
        interfaces: {}

    include-group:
      kind: leaf_node
      multi: true
      description: Include configured members of another group of the same type
      depends: firewall-interface-group
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing interface-group name
      suggestors:
        config-path: {path: 'firewall group interface-group'}
