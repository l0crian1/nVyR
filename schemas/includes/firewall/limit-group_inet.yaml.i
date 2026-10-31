include_schema:
- file: firewall/limit-group_ipv4.yaml.i
  as: inet

  remove:
  - /children/per/choices/source-address
  - /children/per/choices/destination-address
  - /children/source-prefix-length
  - /children/destination-prefix-length

  replace:
    /description: Shared family-neutral rate allowance
    /dependency: firewall-limit-group-inet
    /children/per/validators/list/values: source-port destination-port protocol inbound-interface outbound-interface inbound-link-group
      outbound-link-group source-mac destination-mac packet-mark connection-mark
