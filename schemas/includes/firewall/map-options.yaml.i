children: # map options

  include_schema:
  - file: firewall/group-options.yaml.i
    as: null

  result-type:
    kind: leaf_node
    description: Type of value returned by each map entry
    validators:
      list: {values: verdict address port address-port}
    choices:
      verdict: Firewall action
      address: NAT address
      port: NAT port
      address-port: NAT address and port
