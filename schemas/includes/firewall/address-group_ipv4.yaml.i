ipv4:
  kind: tag_node
  anchor: true
  dependency: firewall-address-group-ipv4
  description: Named IPv4 address group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Group name
  children: # ipv4

    include_schema:
    - file: firewall/geoip.yaml.i
    - file: firewall/dynamic.yaml.i
    - file: firewall/group-description.yaml.i
    - file: nftables/counter.yaml.i
    - file: nftables/last-used.yaml.i

    address:
      kind: leaf_node
      multi: true
      description: IPv4 address, prefix or inclusive range
      strip_kind: ipv4
      validators:
        mode: OR
        address: {version: 4}
        ip-range: {version: 4}
      hints:
        x.x.x.x[/x]: Address or prefix
        start-end: Inclusive address range

    include-group:
      kind: leaf_node
      multi: true
      description: Include configured members of another group of the same type
      depends: firewall-address-group-ipv4
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing address-group IPv4 name
      suggestors:
        config-path: {path: 'firewall group address-group ipv4'}
