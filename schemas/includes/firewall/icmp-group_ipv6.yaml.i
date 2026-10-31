ipv6:
  kind: tag_node
  anchor: true
  dependency: firewall-icmp-group-ipv6
  description: Named IPv6 ICMP type or type/code group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Group name
  children: # ipv6

    include_schema:
    - file: firewall/group-description.yaml.i
    - file: nftables/counter.yaml.i
    - file: nftables/last-used.yaml.i
    - file: nftables/icmpv6-type.yaml.i
      as: type
      remove:
      - /multi
      replace:
        /kind: tag_node
      add:
        /anchor: true
        /children: # type

          code:
            kind: leaf_node
            multi: true
            description: ICMP code or inclusive range valid for this type
            validators:
              integer-range: {minimum: 0, maximum: 255, allow_range: true}
            hints:
              number: Single code valid for this type
              start-end: Inclusive range of codes valid for this type

    match:
      kind: leaf_node
      description: Match types alone or their associated codes
      validators:
        list: {values: 'type type-code'}
      choices:
        type: Match any configured type, regardless of code
        type-code: Match a configured type and its associated code or range
