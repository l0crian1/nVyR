include_schema:
- file: firewall/connection.yaml.i
  add:
    /children/timeout-group:
      kind: leaf_node
      description: Assign a named connection tracking timeout policy
      depends: firewall-timeout-group-ipv4
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Configured timeout group in this address family
      suggestors:
        config-path: {path: 'firewall group timeout-group ipv4'}
    /children/original/children/source-address/validators/address/version: 4
    /children/original/children/source-address/validators/ip-range/version: 4
    /children/original/children/destination-address/validators/address/version: 4
    /children/original/children/destination-address/validators/ip-range/version: 4
    /children/reply/children/source-address/validators/address/version: 4
    /children/reply/children/source-address/validators/ip-range/version: 4
    /children/reply/children/destination-address/validators/address/version: 4
    /children/reply/children/destination-address/validators/ip-range/version: 4
