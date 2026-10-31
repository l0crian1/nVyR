ipv6:
  kind: tag_node
  dependency: firewall-map-ipv6
  description: Named IPv6 map
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Map name
  children: # ipv6 map

    include_schema:
    - file: firewall/map-options.yaml.i
      as: null
    - file: firewall/map-result_ipv6.yaml.i
      as: default-result
      replace:
        /description: Value returned when no map entry matches
      add:
        /anchor: true

    entry:
      kind: tag_node
      anchor: true
      description: Unordered map entry identified by a name or number
      validators:
        regex: {pattern: '[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}'}
      hints:
        name: Entry name or number (does not establish priority)
      children: # entry

        include_schema:
        - file: firewall/group-entry_ipv6.yaml.i
          as: null
        - file: firewall/map-result_ipv6.yaml.i
