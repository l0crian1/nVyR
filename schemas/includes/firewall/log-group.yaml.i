log-group:
  kind: tag_node
  anchor: true
  description: Named NFLOG packet collector and dedicated log file
  dependency: firewall-log-group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Log group name
  children:

    include_schema:
    - file: firewall/group-description.yaml.i

    snaplen:
      kind: leaf_node
      description: Maximum packet bytes copied to the collector (default 65535)
      hints:
        1-65535: Maximum packet bytes copied to the collector (default 65535)
      validators:
        integer-range: {minimum: 1, maximum: 65535}

    queue-threshold:
      kind: leaf_node
      description: Packets batched before delivery to the collector (default 1)
      hints:
        1-65535: Packets batched before delivery to the collector (default 1)
      validators:
        integer-range: {minimum: 1, maximum: 65535}
