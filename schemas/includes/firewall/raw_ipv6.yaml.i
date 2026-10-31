raw:
  kind: node
  description: Prerouting rules before connection tracking
  children: # raw

    include_schema:
    - file: firewall/defaults.yaml.i
      as: null
    - file: firewall/rule_raw_ipv6.yaml.i
      remove:
      - /children/modify/children/tcp-mss/choices
      - /children/outbound-interface
      - /children/outbound-interface-group
      replace:
        /children/modify/children/tcp-mss/validators:
          integer-range: {minimum: 1, maximum: 65535}
