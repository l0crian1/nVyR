include_schema:
- file: firewall/match-group_ipv4.yaml.i
  as: inet

  remove:
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

  replace:
    /dependency: firewall-match-group-inet
    /description: Named family-neutral match-group
