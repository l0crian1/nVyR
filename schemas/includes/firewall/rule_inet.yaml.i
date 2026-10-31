include_schema:
- file: firewall/rule.yaml.i

  remove:
  - /children/modify/children/dscp
  - /children/modify/children/ttl
  - /children/connection/children/limit/children/per/choices/source-address
  - /children/connection/children/limit/children/per/choices/destination-address
  - /children/connection/children/limit/children/source-prefix-length
  - /children/connection/children/limit/children/destination-prefix-length
  - /children/connection/children/family
  - /children/connection/children/original/children/source-address
  - /children/connection/children/original/children/destination-address
  - /children/connection/children/reply/children/source-address
  - /children/connection/children/reply/children/destination-address
  - /children/icmp-group
  - /children/limit/children/per/choices/source-address
  - /children/limit/children/per/choices/destination-address
  - /children/limit/children/source-prefix-length
  - /children/limit/children/destination-prefix-length
  - /children/add-to-group/children/source-address
  - /children/add-to-group/children/destination-address
  - /children/icmp-type
  - /children/icmp-code
  - /children/source-address-group
  - /children/destination-address-group
  - /children/source-domain-group
  - /children/destination-domain-group
  - /children/ttl
  - /children/dscp
  - /children/source-address
  - /children/destination-address
  - /children/reject-response/choices/net-unreachable
  - /children/reject-response/choices/prot-unreachable
  - /children/reject-response/choices/frag-needed
  - /children/reject-response/choices/net-prohibited
  - /children/reject-response/choices/host-prohibited

  replace:
    /children/connection/children/timeout-group/depends: firewall-timeout-group-inet
    /children/connection/children/timeout-group/suggestors/config-path/path: firewall group timeout-group inet
    /children/connection/children/limit/children/per/validators/list/values: source-port destination-port protocol inbound-interface
      outbound-interface inbound-link-group outbound-link-group source-mac destination-mac packet-mark connection-mark
    /children/limit/children/per/validators/list/values: source-port destination-port protocol inbound-interface outbound-interface
      inbound-link-group outbound-link-group source-mac destination-mac packet-mark connection-mark
    /children/limit/children/group/description: Share the allowance owned by a named family-neutral limit group
    /children/limit/children/group/depends: firewall-limit-group-inet
    /children/limit/children/group/suggestors/config-path/path: firewall group limit-group inet
    /children/add-to-group/children/match-group/depends: firewall-match-group-inet
    /children/add-to-group/children/match-group/hints/name: Existing dynamic family-neutral match-group
    /children/add-to-group/children/match-group/suggestors/config-path/path: firewall group match-group inet
    /children/map/depends: firewall-map-inet
    /children/map/hints/name: Existing family-neutral map
    /children/map/suggestors/config-path/path: firewall group map inet
    /children/match-group/depends: firewall-match-group-inet
    /children/match-group/hints/name: Existing family-neutral match-group
    /children/match-group/suggestors/config-path/path: firewall group match-group inet
    /children/jump-target/depends: firewall-chain-inet
    /children/reject-response/validators/list/values: port-unreachable admin-prohibited no-route host-unreachable tcp-reset
