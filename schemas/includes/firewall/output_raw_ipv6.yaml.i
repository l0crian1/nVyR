raw:
  kind: node
  description: Output rules before connection tracking
  children: # raw

    include_schema:
    - file: firewall/defaults.yaml.i
      as: null
    - file: firewall/rule_raw_ipv6.yaml.i
      remove:
      - /children/inbound-interface
      - /children/inbound-interface-group
