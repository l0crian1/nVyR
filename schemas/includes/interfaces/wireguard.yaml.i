wireguard:
  kind: tag_node
  dependency: interface
  anchor: true
  description: WireGuard routed tunnel
  validators:
    regex: {pattern: 'wg[0-9]+'}
  suggestors:
    interfaces: {prefix: wg}
  hints:
    wgN: WireGuard interface name
  script:
    name: wireguard
    priority: 10
  include_schema:
  - file: interfaces/common.yaml.i
    remove:
    - /mac
    - /mtu/default
    - /ip/children/arp-entry
    - /ip/children/arp-cache-timeout
    - /ip/children/arp-filter
    - /ip/children/arp-announce
    - /ip/children/arp-ignore
    - /ip/children/arp-accept
    - /ip/children/arp-notify
    - /ip/children/arp-proxy
    - /ip/children/arp-proxy-pvlan
    - /ip/children/arp-retransmit-interval
    - /ip/children/arp-stale-time
    - /ipv6/children/neighbor
    - /ipv6/children/eui64
    - /ipv6/children/interface-identifier
    replace:
      /address/validators:
        ip-interface: {}
    add:

      /private-key:
        kind: leaf_node
        secret: true
        description: Base64 WireGuard private key
        validators:
          wireguard-key: {}
        hints:
          key: Base64-encoded 32-byte private key

      /listen-port:
        kind: leaf_node
        description: UDP listen port; zero or absence selects an automatic port
        validators:
          integer-range: {minimum: 0, maximum: 65535}
        hints:
          0-65535: UDP listen port

      /firewall-mark:
        kind: leaf_node
        description: Packet mark on encrypted outgoing UDP traffic; zero disables marking
        validators:
          firewall-mark: {}
        hints:
          mark: Unsigned 32-bit decimal or hexadecimal mark

      /peer:
        kind: tag_node
        anchor: true
        description: Named WireGuard peer
        validators:
          regex: {pattern: '[A-Za-z0-9][A-Za-z0-9_-]{0,62}'}
        hints:
          name: Peer name
        children:

          include_schema:
          - file: generic/description.yaml.i
          - file: generic/disable.yaml.i

          public-key:
            kind: leaf_node
            strip_kind: private
            description: Remote peer public key
            validators:
              wireguard-key: {}
            hints:
              key: Base64-encoded 32-byte public key

          preshared-key:
            kind: leaf_node
            secret: true
            description: Optional additional symmetric key
            validators:
              wireguard-key: {}
            hints:
              key: Base64-encoded 32-byte preshared key

          allowed-ips:
            kind: leaf_node
            multi: true
            strip_kind: ip
            description: Remote source prefixes and peer selection for outgoing tunnel traffic; does not install routes
            validators:
              ip-prefix: {}
            hints:
              prefix: IPv4 or IPv6 network prefix

          persistent-keepalive:
            kind: leaf_node
            description: Keepalive interval in seconds; zero or absence disables it
            validators:
              integer-range: {minimum: 0, maximum: 65535}
            hints:
              0-65535: Seconds between keepalives

          endpoint:
            kind: node
            anchor: true
            description: Remote UDP endpoint; may also be learned from authenticated incoming traffic
            children:

              address:
                kind: leaf_node
                strip_kind: ip
                description: Remote IP address or DNS hostname
                validators:
                  wireguard-endpoint: {}
                hints:
                  address: IPv4, IPv6 or hostname

              port:
                kind: leaf_node
                description: Remote UDP port
                validators:
                  integer-range: {minimum: 1, maximum: 65535}
                hints:
                  1-65535: UDP port

              address-family:
                kind: leaf_node
                description: Address family to resolve for a hostname; default auto
                choices:
                  auto: Resolve IPv4 and IPv6
                  ipv4: Resolve IPv4 only
                  ipv6: Resolve IPv6 only
                validators:
                  list: {values: auto ipv4 ipv6}

              resolve-interval:
                kind: leaf_node
                description: Periodic hostname refresh; recent handshakes preserve a roaming endpoint
                validators:
                  duration: {maximum: 31536000}
                hints:
                  duration: Positive duration in s, m, h or d
