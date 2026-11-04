include_schema:
- file: interfaces/address.yaml.i
  replace:
    /description: IPv4/IPv6 address with optional prefix length, or a DHCP client mode
  add:
    /validators/mode: OR
    /validators/list: {values: 'dhcp dhcpv6'}
    /choices:
      dhcpv6: Request an IPv6 address using DHCPv6
      dhcp: Acquire an IPv4 address using DHCP
