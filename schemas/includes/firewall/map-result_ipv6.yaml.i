result:
  kind: node
  description: Value returned when this entry matches
  children: # result

    include_schema:
    - file: firewall/map-result.yaml.i
      as: null
    - file: firewall/jump-target.yaml.i
      add:
        /depends: firewall-chain-ipv6
        /suggestors:
          config-path: {path: 'firewall ipv6 name'}

    address:
      kind: leaf_node
      strip_kind: ipv6
      description: Result IPv6 address
      validators:
        ipv6-address: {}
      hints:
        x:x:x:x:x:x: Result address
