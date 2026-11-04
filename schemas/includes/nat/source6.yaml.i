source:
  kind: node
  description: IPv6 source NAT
  children: # source

    include_schema:
    - file: nat/rule6.yaml.i
      remove:
      - /children/inbound-interface
      - /children/inbound-interface-group
      add:
        /children/translation/children/address/validators/list: {values: masquerade}
        /children/translation/children/address/choices:
          masquerade: Translate to the outgoing interface address
