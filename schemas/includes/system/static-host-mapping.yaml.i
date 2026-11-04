static-host-mapping:
  kind: tag_node
  description: Static names resolved by the router through its hosts file
  strip_kind: private
  validators:
    dns-name: {}
  hints:
    hostname: Canonical hostname, for example nas.home.arpa
  script:
    name: static-host-mapping
    priority: 13
  children:

    address:
      kind: leaf_node
      multi: true
      strip_kind: ip
      description: Address returned for the hostname and its aliases
      validators:
        inet-address: {}
      hints:
        x.x.x.x: IPv4 host address
        x:x:x:x:x:x:x:x: IPv6 host address

    alias:
      kind: leaf_node
      multi: true
      strip_kind: private
      description: Additional name for every address in this mapping
      validators:
        dns-name: {}
      hints:
        hostname: Alternate hostname, for example nas
