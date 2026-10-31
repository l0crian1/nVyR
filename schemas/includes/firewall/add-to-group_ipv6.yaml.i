add-to-group:
  kind: node
  anchor: true
  description: Add or refresh a dynamic group member using packet fields
  children: # add-to-group

    source-address:
      kind: leaf_node
      depends: firewall-address-group-ipv6
      description: Dynamic address-group to update from packet source-address
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing dynamic IPv6 address-group
      suggestors:
        config-path: {path: 'firewall group address-group ipv6'}

    destination-address:
      kind: leaf_node
      depends: firewall-address-group-ipv6
      description: Dynamic address-group to update from packet destination-address
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing dynamic IPv6 address-group
      suggestors:
        config-path: {path: 'firewall group address-group ipv6'}

    match-group:
      kind: leaf_node
      depends: firewall-match-group-ipv6
      description: Dynamic match-group to update from packet match fields
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing dynamic IPv6 match-group
      suggestors:
        config-path: {path: 'firewall group match-group ipv6'}

    timeout:
      kind: leaf_node
      description: Override the target group's default member lifetime
      validators:
        duration: {maximum: 18446744073}
      hints:
        duration: Positive duration in s, m, h or d (maximum 18446744073 seconds)
