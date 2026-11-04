name-server:
  kind: leaf_node
  strip_kind: ip
  multi: true
  description: System DNS server address or interface providing learned DNS
  script:
    name: dns
    priority: 14
  validators:
    mode: OR
    inet-address: {}
    regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
  suggestors:
    interfaces: {}
  hints:
    x.x.x.x: Static IPv4 DNS server
    x:x:x:x:x:x: Static IPv6 DNS server
    interface: Use servers and search domains learned through DHCP or IPv6 RA on this interface
