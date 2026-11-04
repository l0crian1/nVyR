destination:
  kind: node
  description: IPv6 destination NAT
  children: # destination

    include_schema:
    - file: nat/rule6.yaml.i
      remove:
      - /children/outbound-interface
      - /children/outbound-interface-group
