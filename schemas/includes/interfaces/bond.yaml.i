bond:
  include_schema:
  - file: interfaces/common.yaml.i
    add:
      /dhcpv6-options:
        include_schema:
        - file: interfaces/dhcpv6-options.yaml.i
          as: null
      /dhcpv6-pd:
        include_schema:
        - file: interfaces/dhcpv6-pd.yaml.i
          as: null
      /dhcp-options:
        include_schema:
        - file: interfaces/dhcp-options.yaml.i
          as: null
      /vif:
        include_schema:
        - file: interfaces/vif.yaml.i
          as: null
      /mode:
        kind: leaf_node
        description: Bond transmission and failover mode
        validators:
          list: {values: "balance-rr active-backup balance-xor broadcast 802.3ad balance-tlb balance-alb"}
        choices:
          balance-rr: Round-robin transmission
          active-backup: One active member with standby links
          balance-xor: Static aggregation with transmit hashing
          broadcast: Transmit each packet on every active link
          802.3ad: Negotiate aggregators using LACP
          balance-tlb: Adaptive transmit load balancing
          balance-alb: Adaptive transmit and receive load balancing

      /member:
        kind: node
        anchor: true
        description: Bond membership
        children:

          interface:
            kind: tag_node
            anchor: true
            description: Configured interface to attach to this bond
            depends: interface
            validators:
              regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
            hints:
              interface: Member interface name
            suggestors:
              interfaces: {}
            children:

              priority:
                kind: leaf_node
                description: Active member selection priority
                validators:
                  integer-range: {minimum: -2147483648, maximum: 2147483647}
                hints:
                  -2147483648-2147483647: Active member selection priority

              queue-id:
                kind: leaf_node
                description: Transmit queue identifier; zero disables assignment
                validators:
                  integer-range: {minimum: 0, maximum: 65535}
                hints:
                  0-65535: Transmit queue identifier; zero disables assignment

              lacp:
                kind: node
                anchor: true
                description: Member LACP settings
                children:

                  port-priority:
                    kind: leaf_node
                    description: LACP actor port priority
                    validators:
                      integer-range: {minimum: 1, maximum: 65535}
                    hints:
                      1-65535: LACP actor port priority

      /link-monitor:
        kind: node
        anchor: true
        description: Member link health monitoring
        children:

          mii:
            kind: node
            anchor: true
            description: Monitor native carrier state
            children:

              interval:
                kind: leaf_node
                description: Carrier polling interval
                validators:
                  kernel-duration: {minimum: 0, maximum: 2147483647, milliseconds: true}
                hints:
                  duration: Carrier polling interval (ms, s, m, h or d)

              up-delay:
                kind: leaf_node
                description: Delay after carrier recovery
                validators:
                  kernel-duration: {minimum: 0, maximum: 2147483647, milliseconds: true}
                hints:
                  duration: Delay after carrier recovery (ms, s, m, h or d)

              down-delay:
                kind: leaf_node
                description: Delay after carrier loss
                validators:
                  kernel-duration: {minimum: 0, maximum: 2147483647, milliseconds: true}
                hints:
                  duration: Delay after carrier loss (ms, s, m, h or d)

          probe:
            kind: node
            anchor: true
            description: Monitor IPv4 or IPv6 neighbors
            children:

              interval:
                kind: leaf_node
                description: Time between neighbor probes
                validators:
                  kernel-duration: {minimum: 1, maximum: 2147483647, milliseconds: true}
                hints:
                  duration: Time between neighbor probes (ms, s, m, h or d)

              ipv4-target:
                kind: leaf_node
                description: IPv4 neighbor to probe
                multi: true
                strip_kind: ipv4
                validators:
                  ipv4-address: {}
                hints:
                  x.x.x.x: Neighbor address

              ipv6-target:
                kind: leaf_node
                description: IPv6 neighbor to probe
                multi: true
                strip_kind: ipv6
                validators:
                  ipv6-address: {}
                hints:
                  h:h::h: Neighbor address

              missed-max:
                kind: leaf_node
                description: Missed probe intervals before failure
                validators:
                  integer-range: {minimum: 1, maximum: 255}
                hints:
                  1-255: Missed probe intervals before failure

              validate:
                kind: leaf_node
                description: Probe validation and traffic filtering
                validators:
                  list: {values: "none active backup all filter filter-active filter-backup"}
                choices:
                  none: Accept traffic without validation
                  active: Validate the active member
                  backup: Validate backup members
                  all: Validate all members
                  filter: Count only probe traffic
                  filter-active: Filter all members and validate the active member
                  filter-backup: Filter all members and validate backup members

              target-policy:
                kind: leaf_node
                description: Target reachability required in active-backup mode
                validators:
                  list: {values: "any all"}
                choices:
                  any: Any target reachable
                  all: All targets reachable

      /lacp:
        kind: node
        anchor: true
        description: IEEE 802.3ad negotiation
        children:

          passive:
            kind: leaf_node
            description: Wait for the partner to initiate LACP
            valueless: true

          rate:
            kind: leaf_node
            description: Requested partner LACP transmission rate
            validators:
              list: {values: "slow fast"}
            choices:
              slow: Every 30 seconds
              fast: Every second

          min-links:
            kind: leaf_node
            description: Minimum active links required for carrier
            validators:
              integer-range: {minimum: 0, maximum: 2147483647}
            hints:
              0-2147483647: Minimum active links required for carrier

          aggregator-select:
            kind: leaf_node
            description: Active aggregator selection policy
            validators:
              list: {values: "stable bandwidth count actor-port-priority"}
            choices:
              stable: Keep the selected aggregator while usable
              bandwidth: Prefer greatest aggregate bandwidth
              count: Prefer most active ports
              actor-port-priority: Prefer highest sum of local port priorities

          system-priority:
            kind: leaf_node
            description: LACP actor system priority
            validators:
              integer-range: {minimum: 1, maximum: 65535}
            hints:
              1-65535: LACP actor system priority

          system-mac:
            kind: leaf_node
            description: LACP actor system address
            strip_kind: mac
            validators:
              mac: {}
            hints:
              xx:xx:xx:xx:xx:xx: Unicast actor MAC address

          user-port-key:
            kind: leaf_node
            description: User-defined upper ten bits of the port key
            validators:
              integer-range: {minimum: 0, maximum: 1023}
            hints:
              0-1023: User-defined upper ten bits of the port key

          strict:
            kind: leaf_node
            description: Require successful LACP negotiation before forwarding
            valueless: true

          independent-control:
            kind: leaf_node
            description: Control LACP collection and distribution independently
            valueless: true

          broadcast-neighbor:
            kind: leaf_node
            description: Send neighbor discovery packets on all active aggregator members
            valueless: true

      /primary:
        kind: leaf_node
        description: Preferred active member
        validators:
          regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
        hints:
          interface: Member interface name
        suggestors:
          bond-members: {}

      /primary-reselect:
        kind: leaf_node
        description: When to reselect the preferred member
        validators:
          list: {values: "always better failure"}
        choices:
          always: Whenever the primary is available
          better: When the primary has better speed or duplex
          failure: Only after the current active member fails

      /fail-over-mac:
        kind: leaf_node
        description: MAC policy during active-backup failover
        validators:
          list: {values: "none active follow"}
        choices:
          none: Apply the bond MAC to all members
          active: Follow the active member MAC
          follow: Program the bond MAC on the active member at failover

      /peer-notifications:
        kind: leaf_node
        description: Gratuitous ARPs and unsolicited NAs after failover
        validators:
          integer-range: {minimum: 0, maximum: 255}
        hints:
          0-255: Gratuitous ARPs and unsolicited NAs after failover

      /peer-notification-delay:
        kind: leaf_node
        description: Time between peer notifications
        validators:
          kernel-duration: {minimum: 0, maximum: 2147483647, milliseconds: true}
        hints:
          duration: Time between peer notifications (ms, s, m, h or d)

      /resend-igmp:
        kind: leaf_node
        description: IGMP membership reports after failover
        validators:
          integer-range: {minimum: 0, maximum: 255}
        hints:
          0-255: IGMP membership reports after failover

      /transmit-hash-policy:
        kind: leaf_node
        description: Fields used for transmit member selection
        validators:
          list: {values: "layer2 layer2+3 layer3+4 encap2+3 encap3+4 vlan+srcmac"}
        choices:
          layer2: MAC addresses and EtherType
          layer2+3: Ethernet and IP headers
          layer3+4: IP and transport headers
          encap2+3: Inner Ethernet and IP headers when available
          encap3+4: Inner IP and transport headers when available
          vlan+srcmac: VLAN ID and source MAC

      /packets-per-member:
        kind: leaf_node
        description: Round-robin burst size; zero selects a random member per packet
        validators:
          integer-range: {minimum: 0, maximum: 65535}
        hints:
          0-65535: Round-robin burst size; zero selects a random member per packet

      /deliver-inactive-frames:
        kind: leaf_node
        description: Deliver duplicate frames received on inactive ports
        valueless: true

      /learning-packet-interval:
        kind: leaf_node
        description: Time between switch learning packets
        validators:
          kernel-duration: {minimum: 1, maximum: 2147483647, milliseconds: false}
        hints:
          duration: Time between switch learning packets (s, m, h or d)

      /disable-dynamic-load-balancing:
        kind: leaf_node
        description: Disable adaptive redistribution of active flows
        valueless: true
    replace:
      /address:
        include_schema:
        - file: interfaces/address_dhcp.yaml.i
          as: null
  kind: tag_node
  dependency: interface
  anchor: true
  description: Bond interface configuration
  validators:
    regex: {pattern: 'bond[0-9]+'}
  suggestors:
    interfaces: {prefix: bond}
  script:
    name: bond
    priority: 11
    watch:
    - interfaces ethernet
    - interfaces virtual-ethernet
    - interfaces dummy
  hints:
    bondN: Bond interface name
