children:

  remote-as:
    kind: leaf_node
    description: Remote autonomous system number or relationship
    validators:
      bgp-remote-as: {}
    hints:
      1-4294967295: Remote autonomous system number
    choices:
      internal: Use the local AS
      external: Accept a different AS
      auto: Discover the remote AS

  description:
    kind: leaf_node
    description: Neighbor description
    hints:
      text: Neighbor description; quote spaces
    validators:
      text: {}

  password:
    kind: leaf_node
    description: TCP MD5 authentication password
    hints:
      password: TCP MD5 secret, 1-80 UTF-8 bytes; quote spaces
    validators:
      mode: AND
      text: {}
      frr-password: {}
      byte-length:
        minimum: 1
        maximum: 80

  update-source:
    kind: leaf_node
    description: Source interface or IPv4/IPv6 address
    validators:
      bgp-update-source: {}
    depends: interface
    suggestors:
      interfaces: {}
    hints:
      interface: Source interface
      address: Source IPv4 or IPv6 address

  ebgp-multihop:
    kind: leaf_node
    description: Maximum hops to an external neighbor
    validators:
      integer-range:
        minimum: 1
        maximum: 255
    hints:
      1-255: Maximum hops to an external neighbor

  ttl-security:
    kind: node
    description: Protect the session using incoming TTL
    anchor: true
    children:

      hops:
        kind: leaf_node
        description: Maximum hops from the neighbor
        validators:
          integer-range:
            minimum: 1
            maximum: 254
        hints:
          1-254: Maximum hops from the neighbor

  passive:
    kind: leaf_node
    description: Wait for the remote peer to initiate the connection
    valueless: true

  timers:
    kind: node
    description: Neighbor session timers
    anchor: true
    children:

      keepalive:
        kind: leaf_node
        description: Keepalive interval in seconds
        validators:
          integer-range:
            minimum: 0
            maximum: 65535
        hints:
          0-65535: Keepalive interval in seconds

      holdtime:
        kind: leaf_node
        description: Hold time in seconds; zero disables the hold timer
        validators:
          integer-ranges: {ranges: [[0, 0], [3, 65535]]}
        hints:
          0 or 3-65535: Hold time in seconds; zero disables the hold timer

      connect:
        kind: leaf_node
        description: Connection retry interval in seconds
        validators:
          integer-range:
            minimum: 1
            maximum: 65535
        hints:
          1-65535: Connection retry interval in seconds

      advertisement-interval:
        kind: leaf_node
        description: Minimum route advertisement interval in seconds
        validators:
          integer-range:
            minimum: 0
            maximum: 600
        hints:
          0-600: Minimum route advertisement interval in seconds

      delay-open:
        kind: leaf_node
        description: Delay before sending OPEN in seconds
        validators:
          integer-range:
            minimum: 1
            maximum: 240
        hints:
          1-240: Delay before sending OPEN in seconds

  address-family:
    kind: node
    description: Explicitly enabled BGP address families
    anchor: true
    children:

      ipv4-unicast:
        kind: node
        description: Enable IPv4 unicast for this peer
        anchor: true
        children:

          include_schema:
          - file: protocols/bgp/peer-ipv4.yaml.i
            as: null

      ipv4-labeled-unicast:
        kind: node
        description: Enable IPv4 labeled-unicast for this peer
        anchor: true
        children:

          include_schema:
          - file: protocols/bgp/peer-ipv4.yaml.i
            as: null

      ipv6-unicast:
        kind: node
        description: Enable IPv6 unicast for this peer
        anchor: true
        children:

          include_schema:
          - file: protocols/bgp/peer-ipv6.yaml.i
            as: null

      ipv6-labeled-unicast:
        kind: node
        description: Enable IPv6 labeled-unicast for this peer
        anchor: true
        children:

          include_schema:
          - file: protocols/bgp/peer-ipv6.yaml.i
            as: null

  shutdown:
    kind: leaf_node
    description: Administratively shut down this neighbor
    valueless: true

  local-as:
    kind: node
    description: Alternate local AS presented to this peer
    anchor: true
    children:

      number:
        kind: leaf_node
        description: Alternate local autonomous system number
        validators:
          integer-range:
            minimum: 1
            maximum: 4294967295
        hints:
          1-4294967295: Alternate local autonomous system number

      no-prepend:
        kind: node
        description: Do not prepend the alternate AS to received routes
        children:

          replace-as:
            kind: node
            description: Replace the real local AS in advertised paths
            children:

              dual-as:
                kind: leaf_node
                description: Accept sessions using either the real or alternate local AS
                valueless: true

  graceful-shutdown:
    kind: leaf_node
    description: Advertise graceful shutdown to drain traffic before maintenance
    valueless: true

  graceful-restart:
    kind: leaf_node
    description: Per-peer graceful restart behavior
    validators:
      list:
        values: helper restart disable
    choices:
      helper: Retain routes while the peer restarts
      restart: Advertise restart capability
      disable: Disable graceful restart for this peer

  disable-enforce-first-as:
    kind: leaf_node
    description: Do not require the first AS in received paths to match the peer
    valueless: true

  disable-connected-route-check:
    kind: leaf_node
    description: Allow an external peer without a directly connected route
    valueless: true

  port:
    kind: leaf_node
    description: Remote TCP port
    validators:
      integer-range:
        minimum: 1
        maximum: 65535
    hints:
      1-65535: Remote TCP port

  tcp-mss:
    kind: leaf_node
    description: Maximum TCP segment size for this session
    validators:
      integer-range:
        minimum: 1
        maximum: 65535
    hints:
      1-65535: Maximum TCP segment size for this session

  capability:
    kind: node
    description: BGP capability negotiation
    anchor: true
    children:

      extended-nexthop:
        kind: leaf_node
        description: Allow IPv4 routes with IPv6 next hops
        valueless: true

      dynamic:
        kind: leaf_node
        description: Negotiate capability changes without resetting the session
        valueless: true

      link-local:
        kind: leaf_node
        description: Negotiate link-local next-hop encoding
        valueless: true

      software-version:
        kind: leaf_node
        description: Advertise the legacy software-version capability
        valueless: true

      disable-fqdn:
        kind: leaf_node
        description: Do not advertise the hostname capability
        valueless: true

      disable-negotiation:
        kind: leaf_node
        description: Do not send capabilities in OPEN
        valueless: true

      strict-match:
        kind: leaf_node
        description: Require the peer to advertise matching capabilities
        valueless: true

      override:
        kind: leaf_node
        description: Ignore received capability mismatches
        valueless: true

  role:
    kind: node
    description: BGP relationship role and strict negotiation
    anchor: true
    children:

      type:
        kind: leaf_node
        description: Local relationship to the peer
        validators:
          list:
            values: provider customer peer rs-server rs-client
        choices:
          provider: Provider of transit
          customer: Customer of transit
          peer: Settlement-free peer
          rs-server: Route server
          rs-client: Route-server client

      strict:
        kind: leaf_node
        description: Reject peers that do not advertise a compatible role
        valueless: true
