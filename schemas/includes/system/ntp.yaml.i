ntp:
  kind: node
  anchor: true
  description: System time synchronization and NTP client access
  script:
    name: ntp
    priority: 56
    watch:
    - interfaces
  children:

    server:
      kind: tag_node
      anchor: true
      description: Individual upstream NTP server
      validators:
        mode: OR
        inet-address: {}
        dhcp-domain: {}
      hints:
        hostname: NTP server DNS name
        x.x.x.x: IPv4 NTP server
        x:x:x:x:x:x: IPv6 NTP server
      children:

        prefer:
          kind: leaf_node
          valueless: true
          description: Prefer this source among suitable time sources

        nts:
          kind: leaf_node
          valueless: true
          description: Authenticate this source using Network Time Security

    pool:
      kind: tag_node
      anchor: true
      description: DNS pool of upstream NTP servers (up to four responding sources)
      validators:
        dhcp-domain: {}
      hints:
        hostname: DNS name resolving to pool members
      children:

        nts:
          kind: leaf_node
          valueless: true
          description: Authenticate pool sources using Network Time Security

    listen-address:
      kind: node
      anchor: true
      description: Local NTP listener addresses (wildcard when omitted)
      children:

        ipv4:
          kind: leaf_node
          description: Local IPv4 address serving NTP clients
          validators:
            ipv4-address: {}
          hints:
            x.x.x.x: Local IPv4 address

        ipv6:
          kind: leaf_node
          description: Local IPv6 address serving NTP clients
          validators:
            ipv6-address: {}
          hints:
            x:x:x:x:x:x: Local IPv6 address

    allow-client:
      kind: leaf_node
      multi: true
      description: Client address or network allowed to obtain time (none by default)
      validators:
        mode: OR
        inet-address: {}
        ipv4-prefix: {}
        ipv6-prefix: {}
      hints:
        address: IPv4 or IPv6 client address
        prefix: IPv4 or IPv6 client network

    vrf:
      kind: leaf_node
      description: VRF for upstream requests and client listeners (default VRF when omitted)
      hints:
        name: Configured VRF name
      depends: vrf
      validators:
        regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
      suggestors:
        config-path: {path: 'vrf name'}
