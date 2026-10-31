network-settings:
  host-name:
    kind: leaf_node
    description: Hostname inside the container or pod
    hints:
      hostname: Hostname; letters, digits, dots and hyphens, up to 253 characters
    validators:
      regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}'}

  name-server:
    kind: leaf_node
    description: DNS server for the container or pod
    hints:
      address: IPv4 or IPv6 DNS server address
    multi: true
    validators:
      inet-address: {}

  disable-dns:
    kind: leaf_node
    description: Keep the image resolv.conf without Podman generating DNS configuration
    valueless: true

  allow-host-networking:
    kind: leaf_node
    description: Share the router network namespace instead of attaching named networks
    valueless: true

  network:
    kind: tag_node
    description: Attach to a configured Netavark network
    hints:
      name: Configured container network name
    depends: container-network
    validators:
      container-network-name: {}
    suggestors:
      config-path: {path: 'container network'}
    children:

      id:
        kind: leaf_node
        description: Host veth suffix; unique within this container or pod (0-9)
        hints:
          0-9: Host veth suffix; unique within this container or pod (0-9)
        validators:
          regex: {pattern: '[0-9]'}
        default: {mode: direct, value: '0'}

      address:
        kind: leaf_node
        description: Static address; omit for automatic allocation
        hints:
          address: Static IPv4 or IPv6 address inside an attached network subnet; no prefix length
        multi: true
        validators:
          inet-address: {}

      alias:
        kind: leaf_node
        description: DNS alias on this network
        hints:
          hostname: DNS alias on this network, up to 63 characters
        multi: true
        validators:
          regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}'}

  port:
    kind: tag_node
    description: Named published port
    hints:
      name: Name identifying this published port, up to 48 characters; for example HTTPS
    validators:
      regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}'}
    children:

      protocol:
        kind: leaf_node
        description: Transport protocol
        choices:
          tcp: Transmission Control Protocol
          udp: User Datagram Protocol
          sctp: Stream Control Transmission Protocol
        validators:
          list: {values: 'tcp udp sctp'}

      source-address:
        kind: leaf_node
        description: Host listening address; omit to listen on all host IPv4 addresses
        hints:
          address: Local host IPv4 or IPv6 address on which to publish the port
        validators:
          inet-address: {}

      source-port:
        kind: leaf_node
        description: Host listening port
        hints:
          1-65535: Host listening port
        validators:
          integer-range: {minimum: 1, maximum: 65535}

      destination-port:
        kind: leaf_node
        description: Container destination port
        hints:
          1-65535: Container destination port
        validators:
          integer-range: {minimum: 1, maximum: 65535}
