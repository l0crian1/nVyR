ipv6:
  kind: tag_node
  dependency: firewall-match-group-ipv6
  description: Named IPv6 match-group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Match-group name
  children: # ipv6 match-group

    include_schema:
    - file: firewall/dynamic.yaml.i
    - file: firewall/group-options.yaml.i
      as: null

    entry:
      kind: tag_node
      anchor: true
      description: Unordered match-group entry identified by a name or number
      validators:
        regex: {pattern: '[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}'}
      hints:
        name: Entry name or number (does not establish priority)
      children: # entry

        include_schema:
        - file: firewall/group-entry_ipv6.yaml.i
          as: null
