option:
  kind: node
  anchor: true
  description: Options inherited unless overridden in a narrower scope
  children:

    name-server:
      kind: leaf_node
      description: DNS server address
      hints:
        IPv6-address: DNS server address (IPv6)
      validators:
        ipv6-address: {}
      multi: true

    domain-search:
      kind: leaf_node
      description: Domain search suffix
      hints:
        domain: Domain search suffix; for example home.example
      validators:
        dhcp-domain: {}
      multi: true
