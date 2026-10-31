include_schema:
- file: operational/firewall_member_ipv4.yaml.i
  remove:
  - /source-address
  - /destination-address
  - /icmp-type
  - /icmp-code
  - /dscp
  - /connection/children/family
  - /connection/children/original/children/source-address
  - /connection/children/original/children/destination-address
  - /connection/children/reply/children/source-address
  - /connection/children/reply/children/destination-address
