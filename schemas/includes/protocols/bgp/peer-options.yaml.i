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
    description: Explicitly enabled unicast address families
    anchor: true
    children:

      ipv4-unicast:
        kind: node
        description: Enable IPv4 unicast for this peer
        anchor: true
        children:

          route-map:
            kind: node
            description: Routing policy in each direction
            anchor: true
            children:

              import:
                kind: leaf_node
                description: Route-map applied to routes received from this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured route-map
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

              export:
                kind: leaf_node
                description: Route-map applied to routes advertised to this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured route-map
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

          prefix-list:
            kind: node
            description: Prefix filtering in each direction
            anchor: true
            children:

              in:
                kind: leaf_node
                description: Prefix-list applied to routes received from this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured prefix-list
                depends: policy-prefix-list-ipv4
                suggestors:
                  config-path:
                    path: policy prefix-list ipv4

              out:
                kind: leaf_node
                description: Prefix-list applied to routes advertised to this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured prefix-list
                depends: policy-prefix-list-ipv4
                suggestors:
                  config-path:
                    path: policy prefix-list ipv4

          access-list:
            kind: node
            description: Access-list filtering in each direction
            anchor: true
            children:

              in:
                kind: leaf_node
                description: Access-list applied to routes received from this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured access-list
                depends: policy-access-list-ipv4
                suggestors:
                  config-path:
                    path: policy access-list ipv4

              out:
                kind: leaf_node
                description: Access-list applied to routes advertised to this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured access-list
                depends: policy-access-list-ipv4
                suggestors:
                  config-path:
                    path: policy access-list ipv4

          next-hop-self:
            kind: node
            description: Advertise this router as next hop
            anchor: true
            children:

              force:
                kind: leaf_node
                description: Also replace next hops on routes learned through iBGP
                valueless: true

          route-reflector-client:
            kind: leaf_node
            description: Treat this internal peer as a route-reflector client
            valueless: true

          default-originate:
            kind: node
            description: Originate a default route, optionally gated by policy
            anchor: true
            children:

              route-map:
                kind: leaf_node
                description: Configured route-map
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured route-map
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

          maximum-prefix:
            kind: node
            description: Limit routes received from this peer
            anchor: true
            children:

              limit:
                kind: leaf_node
                description: Maximum received prefixes
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 4294967295
                hints:
                  1-4294967295: Maximum received prefixes

              threshold:
                kind: leaf_node
                description: Warning threshold as a percentage of the limit
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 100
                hints:
                  1-100: Warning threshold as a percentage of the limit

              warning-only:
                kind: leaf_node
                description: Warn without closing the session
                valueless: true

              restart:
                kind: leaf_node
                description: Minutes before restarting a session closed by the limit
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 65535
                hints:
                  1-65535: Minutes before restarting a session closed by the limit

              force:
                kind: leaf_node
                description: Count filtered routes too; requires inbound soft reconfiguration
                valueless: true

          send-community:
            kind: leaf_node
            description: Community classes to send; all classes when omitted
            validators:
              list:
                values: standard extended large
            multi: true
            choices:
              standard: Standard communities
              extended: Extended communities
              large: Large communities

          disable:
            kind: leaf_node
            description: Disable this family, including inherited activation
            valueless: true

          allowas-in:
            kind: node
            description: Accept routes containing the local AS
            anchor: true
            children:

              count:
                kind: leaf_node
                description: Maximum occurrences of the local AS
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 10
                hints:
                  1-10: Maximum occurrences of the local AS

              origin:
                kind: leaf_node
                description: Allow the local AS only at the origin of the path
                valueless: true

              route-map:
                kind: leaf_node
                description: Select routes allowed to contain the local AS
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Select routes allowed to contain the local AS
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

          as-override:
            kind: leaf_node
            description: Replace occurrences of the remote AS with the local AS on export
            valueless: true

          remove-private-as:
            kind: node
            description: Remove private AS numbers from advertised paths
            children:

              all:
                kind: node
                description: Remove private AS numbers even in mixed paths
                children:

                  replace:
                    kind: leaf_node
                    description: Replace removed private AS numbers with the local AS
                    valueless: true

              replace:
                kind: leaf_node
                description: Replace removed private AS numbers with the local AS
                valueless: true

          soft-reconfiguration:
            kind: node
            description: Retain received routes for policy reevaluation
            children:

              inbound:
                kind: leaf_node
                description: Store unmodified received routes
                valueless: true

          maximum-prefix-out:
            kind: leaf_node
            description: Maximum prefixes advertised to the peer
            validators:
              integer-range:
                minimum: 1
                maximum: 4294967295
            hints:
              1-4294967295: Maximum prefixes advertised to the peer

          conditional-advertisement:
            kind: node
            description: Advertise routes depending on another route being present
            anchor: true
            children:

              advertise-map:
                kind: leaf_node
                description: Routes to advertise conditionally
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Routes to advertise conditionally
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

              exist-map:
                kind: leaf_node
                description: Advertise when a matching route exists
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Advertise when a matching route exists
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

              non-exist-map:
                kind: leaf_node
                description: Advertise when no matching route exists
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Advertise when no matching route exists
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

          addpath:
            kind: node
            description: Advertise and receive multiple paths for a prefix
            anchor: true
            children:

              transmit:
                kind: node
                description: Select additional advertised paths
                anchor: true
                children:

                  all:
                    kind: leaf_node
                    description: Advertise every eligible path
                    valueless: true

                  best-selected:
                    kind: leaf_node
                    description: Number of best paths to advertise
                    validators:
                      integer-range:
                        minimum: 1
                        maximum: 6
                    hints:
                      1-6: Number of best paths to advertise

              disable-receive:
                kind: leaf_node
                description: Disable receiving additional paths
                valueless: true

              receive-limit:
                kind: leaf_node
                description: Maximum received paths per prefix
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 65535
                hints:
                  1-65535: Maximum received paths per prefix

          route-server-client:
            kind: leaf_node
            description: Treat this peer as a route-server client
            valueless: true

          attribute-unchanged:
            kind: node
            description: Preserve attributes when advertising routes
            anchor: true
            children:

              as-path:
                kind: leaf_node
                description: Preserve the AS path
                valueless: true

              next-hop:
                kind: leaf_node
                description: Preserve the next hop
                valueless: true

              med:
                kind: leaf_node
                description: Preserve the multi-exit discriminator
                valueless: true

          weight:
            kind: leaf_node
            description: Local weight for routes received from this peer
            validators:
              integer-range:
                minimum: 0
                maximum: 65535
            hints:
              0-65535: Local weight for routes received from this peer

          as-path-list:
            kind: node
            description: Filter routes using AS-path lists
            anchor: true
            children:

              import:
                kind: leaf_node
                description: AS-path list for received routes
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: AS-path list for received routes
                depends: policy-as-path-list
                suggestors:
                  config-path:
                    path: policy as-path-list

              export:
                kind: leaf_node
                description: AS-path list for advertised routes
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: AS-path list for advertised routes
                depends: policy-as-path-list
                suggestors:
                  config-path:
                    path: policy as-path-list

          unsuppress-map:
            kind: leaf_node
            description: Select suppressed aggregate components to advertise
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Select suppressed aggregate components to advertise
            depends: policy-route-map
            suggestors:
              config-path:
                path: policy route-map

      ipv6-unicast:
        kind: node
        description: Enable IPv6 unicast for this peer
        anchor: true
        children:

          route-map:
            kind: node
            description: Routing policy in each direction
            anchor: true
            children:

              import:
                kind: leaf_node
                description: Route-map applied to routes received from this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured route-map
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

              export:
                kind: leaf_node
                description: Route-map applied to routes advertised to this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured route-map
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

          prefix-list:
            kind: node
            description: Prefix filtering in each direction
            anchor: true
            children:

              in:
                kind: leaf_node
                description: Prefix-list applied to routes received from this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured prefix-list
                depends: policy-prefix-list-ipv6
                suggestors:
                  config-path:
                    path: policy prefix-list ipv6

              out:
                kind: leaf_node
                description: Prefix-list applied to routes advertised to this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured prefix-list
                depends: policy-prefix-list-ipv6
                suggestors:
                  config-path:
                    path: policy prefix-list ipv6

          access-list:
            kind: node
            description: Access-list filtering in each direction
            anchor: true
            children:

              in:
                kind: leaf_node
                description: Access-list applied to routes received from this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured access-list
                depends: policy-access-list-ipv6
                suggestors:
                  config-path:
                    path: policy access-list ipv6

              out:
                kind: leaf_node
                description: Access-list applied to routes advertised to this peer
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured access-list
                depends: policy-access-list-ipv6
                suggestors:
                  config-path:
                    path: policy access-list ipv6

          next-hop-self:
            kind: node
            description: Advertise this router as next hop
            anchor: true
            children:

              force:
                kind: leaf_node
                description: Also replace next hops on routes learned through iBGP
                valueless: true

          route-reflector-client:
            kind: leaf_node
            description: Treat this internal peer as a route-reflector client
            valueless: true

          default-originate:
            kind: node
            description: Originate a default route, optionally gated by policy
            anchor: true
            children:

              route-map:
                kind: leaf_node
                description: Configured route-map
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Configured route-map
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

          maximum-prefix:
            kind: node
            description: Limit routes received from this peer
            anchor: true
            children:

              limit:
                kind: leaf_node
                description: Maximum received prefixes
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 4294967295
                hints:
                  1-4294967295: Maximum received prefixes

              threshold:
                kind: leaf_node
                description: Warning threshold as a percentage of the limit
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 100
                hints:
                  1-100: Warning threshold as a percentage of the limit

              warning-only:
                kind: leaf_node
                description: Warn without closing the session
                valueless: true

              restart:
                kind: leaf_node
                description: Minutes before restarting a session closed by the limit
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 65535
                hints:
                  1-65535: Minutes before restarting a session closed by the limit

              force:
                kind: leaf_node
                description: Count filtered routes too; requires inbound soft reconfiguration
                valueless: true

          send-community:
            kind: leaf_node
            description: Community classes to send; all classes when omitted
            validators:
              list:
                values: standard extended large
            multi: true
            choices:
              standard: Standard communities
              extended: Extended communities
              large: Large communities

          disable:
            kind: leaf_node
            description: Disable this family, including inherited activation
            valueless: true

          allowas-in:
            kind: node
            description: Accept routes containing the local AS
            anchor: true
            children:

              count:
                kind: leaf_node
                description: Maximum occurrences of the local AS
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 10
                hints:
                  1-10: Maximum occurrences of the local AS

              origin:
                kind: leaf_node
                description: Allow the local AS only at the origin of the path
                valueless: true

              route-map:
                kind: leaf_node
                description: Select routes allowed to contain the local AS
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Select routes allowed to contain the local AS
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

          as-override:
            kind: leaf_node
            description: Replace occurrences of the remote AS with the local AS on export
            valueless: true

          remove-private-as:
            kind: node
            description: Remove private AS numbers from advertised paths
            children:

              all:
                kind: node
                description: Remove private AS numbers even in mixed paths
                children:

                  replace:
                    kind: leaf_node
                    description: Replace removed private AS numbers with the local AS
                    valueless: true

              replace:
                kind: leaf_node
                description: Replace removed private AS numbers with the local AS
                valueless: true

          soft-reconfiguration:
            kind: node
            description: Retain received routes for policy reevaluation
            children:

              inbound:
                kind: leaf_node
                description: Store unmodified received routes
                valueless: true

          maximum-prefix-out:
            kind: leaf_node
            description: Maximum prefixes advertised to the peer
            validators:
              integer-range:
                minimum: 1
                maximum: 4294967295
            hints:
              1-4294967295: Maximum prefixes advertised to the peer

          conditional-advertisement:
            kind: node
            description: Advertise routes depending on another route being present
            anchor: true
            children:

              advertise-map:
                kind: leaf_node
                description: Routes to advertise conditionally
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Routes to advertise conditionally
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

              exist-map:
                kind: leaf_node
                description: Advertise when a matching route exists
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Advertise when a matching route exists
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

              non-exist-map:
                kind: leaf_node
                description: Advertise when no matching route exists
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: Advertise when no matching route exists
                depends: policy-route-map
                suggestors:
                  config-path:
                    path: policy route-map

          addpath:
            kind: node
            description: Advertise and receive multiple paths for a prefix
            anchor: true
            children:

              transmit:
                kind: node
                description: Select additional advertised paths
                anchor: true
                children:

                  all:
                    kind: leaf_node
                    description: Advertise every eligible path
                    valueless: true

                  best-selected:
                    kind: leaf_node
                    description: Number of best paths to advertise
                    validators:
                      integer-range:
                        minimum: 1
                        maximum: 6
                    hints:
                      1-6: Number of best paths to advertise

              disable-receive:
                kind: leaf_node
                description: Disable receiving additional paths
                valueless: true

              receive-limit:
                kind: leaf_node
                description: Maximum received paths per prefix
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 65535
                hints:
                  1-65535: Maximum received paths per prefix

          route-server-client:
            kind: leaf_node
            description: Treat this peer as a route-server client
            valueless: true

          attribute-unchanged:
            kind: node
            description: Preserve attributes when advertising routes
            anchor: true
            children:

              as-path:
                kind: leaf_node
                description: Preserve the AS path
                valueless: true

              next-hop:
                kind: leaf_node
                description: Preserve the next hop
                valueless: true

              med:
                kind: leaf_node
                description: Preserve the multi-exit discriminator
                valueless: true

          weight:
            kind: leaf_node
            description: Local weight for routes received from this peer
            validators:
              integer-range:
                minimum: 0
                maximum: 65535
            hints:
              0-65535: Local weight for routes received from this peer

          as-path-list:
            kind: node
            description: Filter routes using AS-path lists
            anchor: true
            children:

              import:
                kind: leaf_node
                description: AS-path list for received routes
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: AS-path list for received routes
                depends: policy-as-path-list
                suggestors:
                  config-path:
                    path: policy as-path-list

              export:
                kind: leaf_node
                description: AS-path list for advertised routes
                validators:
                  regex:
                    pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
                hints:
                  name: AS-path list for advertised routes
                depends: policy-as-path-list
                suggestors:
                  config-path:
                    path: policy as-path-list

          unsuppress-map:
            kind: leaf_node
            description: Select suppressed aggregate components to advertise
            validators:
              regex:
                pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
            hints:
              name: Select suppressed aggregate components to advertise
            depends: policy-route-map
            suggestors:
              config-path:
                path: policy route-map

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
