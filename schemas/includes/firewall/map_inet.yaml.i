include_schema:
- file: firewall/map_ipv4.yaml.i
  as: inet

  remove:
  - /children/default-result/children/address
  - /children/default-result/children/port
  - /children/match/children/connection/children/family
  - /children/match/children/connection/children/original/children/source-address
  - /children/match/children/connection/children/original/children/destination-address
  - /children/match/children/connection/children/reply/children/source-address
  - /children/match/children/connection/children/reply/children/destination-address
  - /children/match/children/source-address
  - /children/match/children/destination-address
  - /children/match/children/dscp
  - /children/match/children/icmp-type
  - /children/match/children/icmp-code
  - /children/entry/children/connection/children/family
  - /children/entry/children/connection/children/original/children/source-address
  - /children/entry/children/connection/children/original/children/destination-address
  - /children/entry/children/connection/children/reply/children/source-address
  - /children/entry/children/connection/children/reply/children/destination-address
  - /children/entry/children/icmp-type
  - /children/entry/children/icmp-code
  - /children/entry/children/dscp
  - /children/entry/children/source-address
  - /children/entry/children/destination-address
  - /children/entry/children/result/children/address
  - /children/entry/children/result/children/port
  - /children/result-type/choices/address
  - /children/result-type/choices/port
  - /children/result-type/choices/address-port

  replace:
    /children/default-result/children/jump-target/depends: firewall-chain-inet
    /children/default-result/children/jump-target/suggestors/config-path/path: firewall inet name
    /dependency: firewall-map-inet
    /description: Named family-neutral map
    /children/entry/children/result/children/jump-target/depends: firewall-chain-inet
    /children/entry/children/result/children/jump-target/suggestors/config-path/path: firewall inet name
    /children/result-type/validators/list/values: verdict
