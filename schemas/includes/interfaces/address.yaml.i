address:
  kind: leaf_node
  strip_kind: ip
  description: IP prefix
  multi: true
  validators:
    address: {}
  hints:
    x.x.x.x/x: IPv4 address with mask
    x:x:x:x:x:x/x: IPv6 address with mask
