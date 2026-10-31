include_schema:
- file: firewall/rule_ipv6.yaml.i
  remove:
  - /children/modify/children/connection-mark
  - /children/connection/children/timeout-group
  add:
    /children/notrack:
      kind: leaf_node
      description: Exclude matching packets from connection tracking
      valueless: true
