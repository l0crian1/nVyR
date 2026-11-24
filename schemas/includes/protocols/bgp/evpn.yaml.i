l2vpn-evpn:
  kind: node
  description: Ethernet VPN address family
  anchor: true
  children:

    advertise-all-vni:
      kind: leaf_node
      description: Advertise locally discovered VNIs
      valueless: true

    advertise-default-gw:
      kind: leaf_node
      description: Advertise default gateway MAC/IP routes
      valueless: true

    advertise-svi-ip:
      kind: leaf_node
      description: Advertise local SVI MAC/IP routes
      valueless: true

    flooding:
      kind: leaf_node
      description: BUM traffic replication
      validators:
        list: {values: 'head-end-replication disable'}
      choices:
        'head-end-replication': Replicate traffic to remote VTEPs
        'disable': Disable flooding

    auto-route-target:
      kind: node
      description: Automatic route target derivation
      anchor: true
      children:

        rfc8365-compatible:
          kind: leaf_node
          description: Derive route targets according to RFC 8365
          valueless: true

    duplicate-address-detection:
      kind: node
      description: Detect duplicate MAC or IP addresses
      anchor: true
      children:

        disable:
          kind: leaf_node
          description: Disable duplicate address detection
          valueless: true

        max-moves:
          kind: leaf_node
          description: Number of moves to trigger detection
          validators:
            integer-range: {minimum: 2, maximum: 1000}
          hints:
            2-1000: MAC moves before detecting a duplicate

        time:
          kind: leaf_node
          description: Observation window in seconds
          validators:
            integer-range: {minimum: 2, maximum: 1800}
          hints:
            2-1800: Observation window in seconds

        freeze:
          kind: leaf_node
          description: Freeze duplicates permanently or for a duration
          validators:
            mode: OR
            integer-range: {minimum: 30, maximum: 3600}
            list: {values: permanent}
          choices:
            permanent: Freeze until cleared
          hints:
            30-3600: Freeze time in seconds

    enable-resolve-overlay-index:
      kind: leaf_node
      description: Resolve Type 5 gateway IP overlay indexes
      valueless: true

    vni:
      kind: tag_node
      description: Policy for one L2VNI
      anchor: true
      validators:
        mode: AND
        regex: {pattern: '[1-9][0-9]{0,7}'}
        integer-range: {minimum: 1, maximum: 16777215}
      hints:
        1-16777215: VXLAN network identifier
      children:

        include_schema:
        - file: protocols/bgp/evpn-targets.yaml.i
          as: null

        advertise-default-gw:
          kind: leaf_node
          description: Advertise default gateway MAC/IP routes
          valueless: true

        advertise-svi-ip:
          kind: leaf_node
          description: Advertise local SVI MAC/IP routes
          valueless: true

        advertise-subnet:
          kind: leaf_node
          description: Advertise connected SVI subnets as Type 5 routes
          valueless: true

        flooding:
          kind: leaf_node
          description: BUM traffic replication
          validators:
            list: {values: 'head-end-replication disable'}
          choices:
            'head-end-replication': Replicate traffic to remote VTEPs
            'disable': Disable flooding
