children:

  site-of-origin:
    kind: leaf_node
    description: Site-of-origin community used to prevent routes returning to their site
    hints:
      soo: ASN:number or IPv4:number
    validators:
      bgp-rd-rt: {}

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
