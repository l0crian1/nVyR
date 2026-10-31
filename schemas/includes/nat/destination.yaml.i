destination:
  kind: node
  description: IPv4 destination NAT
  children: # destination

    include_schema:
    - file: nat/rule.yaml.i
      remove:
      - /children/outbound-interface
      - /children/outbound-interface-group
