include_schema:
- file: firewall/connection-entry.yaml.i
  add:
    /children/original/children/source-address/validators/address/version: 6
    /children/original/children/source-address/validators/ip-range/version: 6
    /children/original/children/destination-address/validators/address/version: 6
    /children/original/children/destination-address/validators/ip-range/version: 6
    /children/reply/children/source-address/validators/address/version: 6
    /children/reply/children/source-address/validators/ip-range/version: 6
    /children/reply/children/destination-address/validators/address/version: 6
    /children/reply/children/destination-address/validators/ip-range/version: 6
