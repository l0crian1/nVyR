option:
  kind: node
  anchor: true
  description: Options inherited unless overridden in a narrower scope
  children:

    name-server:
      kind: leaf_node
      description: DNS server address
      hints:
        x.x.x.x: DNS server address (IPv4)
      validators:
        ipv4-address: {}
      multi: true

    domain-search:
      kind: leaf_node
      description: Domain search suffix
      hints:
        domain: Domain search suffix; for example home.example
      validators:
        dhcp-domain: {}
      multi: true

    domain-name:
      kind: leaf_node
      description: Client domain name
      hints:
        domain: Client domain name; for example home.example
      validators:
        dhcp-domain: {}

    ntp-server:
      kind: leaf_node
      description: NTP server address
      hints:
        x.x.x.x: NTP server address (IPv4)
      validators:
        ipv4-address: {}
      multi: true

    default-router:
      kind: leaf_node
      description: Default gateway address
      hints:
        x.x.x.x: Default gateway address (IPv4)
      validators:
        ipv4-address: {}
