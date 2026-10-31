lookup:
  kind: tag_node
  anchor: true
  description: Resolve DNS records or reverse lookup an IP address
  command: ['resolver.nvyr.op', 'lookup', '@line']
  validators:
    regex: {pattern: '[A-Za-z0-9_][A-Za-z0-9_.:-]{0,252}'}
  hints:
    name: DNS name (A and AAAA by default)
    address: IP address for a reverse lookup
  children:

    type:
      kind: leaf_node
      description: DNS record type
      validators:
        list: {values: 'a aaaa mx txt ns cname soa srv caa ptr'}
      choices:
        a: IPv4 addresses
        aaaa: IPv6 addresses
        mx: Mail exchangers and preferences
        txt: Text records
        ns: Authoritative name servers
        cname: Canonical name aliases
        soa: Zone authority information
        srv: Service locations, priorities and weights
        caa: Certificate authority authorization
        ptr: Reverse lookup pointers

    server:
      kind: leaf_node
      description: Query a specific DNS server instead of the system resolvers
      validators:
        mode: OR
        ipv4-address: {}
        ipv6-address: {}
      hints:
        x.x.x.x: IPv4 DNS server address
        x:x:x:x:x:x: IPv6 DNS server address
