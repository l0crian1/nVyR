include_schema:
- file: interfaces/address.yaml.i
  replace:
    /description: IPv4/IPv6 address with optional prefix length, or dhcp for DHCPv4
  add:
    /validators/mode: OR
    /validators/list: {values: dhcp}
    /choices:
      dhcp: Acquire an IPv4 address using DHCP
