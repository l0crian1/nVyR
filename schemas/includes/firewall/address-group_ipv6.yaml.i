ipv6:
  kind: tag_node
  anchor: true
  dependency: firewall-address-group-ipv6
  description: Named IPv6 address group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Group name
  children: # ipv6

    include_schema:
    - file: firewall/geoip.yaml.i
    - file: firewall/dynamic.yaml.i
    - file: firewall/group-description.yaml.i
    - file: nftables/counter.yaml.i
    - file: nftables/last-used.yaml.i

    address:
      kind: leaf_node
      multi: true
      description: IPv6 address, prefix or inclusive range
      strip_kind: ipv6
      validators:
        mode: OR
        address: {version: 6}
        ip-range: {version: 6}
      hints:
        x:x:x:x:x:x[/x]: Address or prefix
        start-end: Inclusive address range

    include-group:
      kind: leaf_node
      multi: true
      description: Include configured members of another group of the same type
      depends: firewall-address-group-ipv6
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing address-group IPv6 name
      suggestors:
        config-path: {path: 'firewall group address-group ipv6'}
