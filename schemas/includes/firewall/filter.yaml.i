filter:
  kind: node
  description: Packet filtering rules and default verdict
  children: # filter

    include_schema:
    - file: firewall/defaults.yaml.i
      as: null
    - file: firewall/rule.yaml.i
