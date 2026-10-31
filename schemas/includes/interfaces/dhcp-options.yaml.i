dhcp-options:
  kind: node
  anchor: true
  description: DHCPv4 client identity and lease handling
  children:

    client-id:
      kind: node
      description: Override the MAC-based DHCP client identifier
      children:

        text:
          kind: leaf_node
          description: Text identifier, sent with the non-hardware type byte
          validators:
            byte-length: {minimum: 1, maximum: 254}
          hints:
            text: Client identifier; quote spaces

        hex:
          kind: leaf_node
          description: Complete client identifier including its type byte
          validators:
            dhcp-identifier: {minimum: 2, maximum: 255}
          hints:
            hex: Colon-separated bytes, for example 01:02:00:00:00:00:01

    default-route-distance:
      kind: leaf_node
      description: Administrative distance for DHCP default routes
      validators:
        integer-range: {minimum: 1, maximum: 254}
      hints:
        1-254: Administrative distance; lower is preferred
      default:
        mode: direct
        value: '210'

    host-name:
      kind: leaf_node
      description: Hostname sent to the DHCP server; defaults to the system hostname
      validators:
        dhcp-domain: {}
      hints:
        hostname: Hostname or fully qualified hostname

    mtu:
      kind: leaf_node
      valueless: true
      description: Use the server MTU while leased; otherwise use the interface MTU

    no-default-route:
      kind: leaf_node
      valueless: true
      description: Ignore DHCP default routes, retaining other advertised routes

    user-class:
      kind: leaf_node
      description: User class sent as DHCP option 77
      validators:
        byte-length: {minimum: 1, maximum: 254}
      hints:
        text: User class; quote spaces

    vendor-class-id:
      kind: leaf_node
      description: Vendor class sent as DHCP option 60
      validators:
        byte-length: {minimum: 1, maximum: 255}
      hints:
        text: Vendor class identifier; quote spaces
