limit:
  kind: node
  anchor: true
  description: Match packets below or above a packet or byte rate
  children: # limit

    include_schema:
    - file: firewall/limit-options.yaml.i
      as: null
    - file: firewall/limit-reference_ipv4.yaml.i
