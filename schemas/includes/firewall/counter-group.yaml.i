counter-group:
  kind: tag_node
  description: Shared packet and byte counter
  dependency: firewall-counter-group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Counter group name
  children: # counter-group

    include_schema:
    - file: firewall/group-description.yaml.i
