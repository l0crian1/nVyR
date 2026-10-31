quota:
  kind: node
  anchor: true
  description: Match cumulative traffic against a byte allowance
  children: # quota

    include_schema:
    - file: firewall/quota-options.yaml.i
      as: null

    group:
      kind: leaf_node
      description: Shared quota group
      depends: firewall-quota-group
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Quota group name
      suggestors:
        config-path: {path: 'firewall group quota-group'}
