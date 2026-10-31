result:
  kind: node
  description: Value returned when this entry matches
  children: # result

    include_schema:
    - file: firewall/map-result.yaml.i
      as: null
    - file: firewall/jump-target.yaml.i
      add:
        /depends: firewall-chain-ipv4
        /suggestors:
          config-path: {path: 'firewall ipv4 name'}

    address:
      kind: leaf_node
      strip_kind: ipv4
      description: Result IPv4 address
      validators:
        ipv4-address: {}
      hints:
        x.x.x.x: Result address
