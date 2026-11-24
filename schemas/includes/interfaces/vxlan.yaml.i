vxlan:
  kind: tag_node
  dependency: interface
  anchor: true
  description: Virtual extensible LAN tunnel interface
  validators:
    regex: {pattern: 'vxlan[0-9]+'}
  hints:
    vxlanN: VXLAN interface name
  suggestors:
    interfaces: {prefix: vxlan}
  script:
    name: bridge
    priority: 12
  include_schema:
  - file: interfaces/common.yaml.i
    remove:
    - /mtu/default
    replace:
      /address/validators:
        ip-interface: {}
    add:

      /vni:
        kind: leaf_node
        description: Fixed VXLAN network identifier
        validators:
          integer-range: {minimum: 0, maximum: 16777215}
        hints:
          0-16777215: Fixed VXLAN network identifier

      /external:
        kind: node
        anchor: true
        description: Externally controlled VXLAN device
        children:
          vni-filter:
            kind: leaf_node
            description: Accept only mapped VNIs
            valueless: true

          vlan:
            kind: tag_node
            anchor: true
            description: Bridge VLAN mapped on this port
            validators:
              integer-range: {minimum: 1, maximum: 4094}
            hints:
              1-4094: Bridge VLAN ID
            children:
              vni:
                kind: leaf_node
                description: Tunnel identifier for this VLAN
                validators:
                  integer-range: {minimum: 0, maximum: 16777215}
                hints:
                  0-16777215: Tunnel identifier for this VLAN

      /source-address:
        kind: leaf_node
        description: Local underlay address
        validators:
          mode: OR
          ipv4-address: {}
          ipv6-address: {}
        strip_kind: ip
        hints:
          address: Local underlay address

      /source-interface:
        kind: leaf_node
        description: Underlying network interface
        validators:
          regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
        depends: interface
        suggestors:
          interfaces: {}
        hints:
          interface: Configured underlay interface

      /remote:
        kind: leaf_node
        description: Default unicast VTEP
        validators:
          mode: OR
          ipv4-address: {}
          ipv6-address: {}
        strip_kind: ip
        hints:
          address: Default unicast VTEP

      /multicast-group:
        kind: leaf_node
        description: Underlay multicast group
        validators:
          mode: OR
          ipv4-address: {}
          ipv6-address: {}
        strip_kind: ip
        hints:
          address: Underlay multicast group

      /destination-port:
        kind: leaf_node
        description: VXLAN UDP destination port
        validators:
          integer-range: {minimum: 1, maximum: 65535}
        hints:
          1-65535: VXLAN UDP destination port

      /source-port:
        kind: node
        anchor: true
        description: UDP source port range
        children:
          minimum:
            kind: leaf_node
            description: Lowest port
            validators:
              integer-range: {minimum: 0, maximum: 65535}
            hints:
              0-65535: Lowest port

          maximum:
            kind: leaf_node
            description: Highest port
            validators:
              integer-range: {minimum: 0, maximum: 65535}
            hints:
              0-65535: Highest port

      /ttl:
        kind: leaf_node
        description: Outer IP time to live
        validators:
          mode: OR
          integer-range: {minimum: 1, maximum: 255}
          list: {values: "auto inherit"}
        choices:
          auto: Use the kernel default
          inherit: Copy the inner TTL
        hints:
          1-255: Explicit hop limit

      /tos:
        kind: leaf_node
        description: Outer IP traffic class
        validators:
          mode: OR
          integer-range: {minimum: 0, maximum: 255}
          list: {values: "inherit"}
        choices:
          inherit: Copy the inner traffic class
        hints:
          0-255: Traffic class

      /dont-fragment:
        kind: leaf_node
        description: IPv4 outer header DF policy
        validators:
          list: {values: "unset set inherit"}
        choices:
          unset: Clear DF
          set: Set DF
          inherit: Copy the inner DF bit

      /flow-label:
        kind: leaf_node
        description: Outer IPv6 flow label
        validators:
          integer-range: {minimum: 0, maximum: 1048575}
        hints:
          0-1048575: Outer IPv6 flow label

      /learning:
        kind: node
        anchor: true
        description: VXLAN forwarding database learning
        children:
          disable:
            kind: leaf_node
            description: Disable tunnel MAC learning
            valueless: true

          ageing-time:
            kind: leaf_node
            description: Time before learned entries expire
            validators:
              kernel-duration: {minimum: 0, maximum: 4294967295}
            hints:
              duration: Time in seconds, minutes, hours or days

          maximum-entries:
            kind: leaf_node
            description: Limit learned entries (zero is unlimited)
            validators:
              integer-range: {minimum: 0, maximum: 4294967295}
            hints:
              0-4294967295: Limit learned entries (zero is unlimited)

      /proxy:
        kind: leaf_node
        description: Enable ARP proxy
        valueless: true

      /route-short-circuit:
        kind: leaf_node
        description: Enable route short circuit
        valueless: true

      /miss-notification:
        kind: node
        anchor: true
        description: Netlink miss notifications
        children:
          l2:
            kind: leaf_node
            description: Report missing MAC addresses
            valueless: true

          l3:
            kind: leaf_node
            description: Report missing IP addresses
            valueless: true

      /checksum:
        kind: node
        anchor: true
        description: UDP tunnel checksums
        children:
          ipv4:
            kind: leaf_node
            description: IPv4 UDP checksum policy
            validators:
              list: {values: "enable disable"}
            choices:
              enable: Generate IPv4 UDP checksums
              disable: Omit IPv4 UDP checksums

          ipv6-zero-transmit:
            kind: leaf_node
            description: Send IPv6 packets with zero UDP checksum
            valueless: true

          ipv6-zero-receive:
            kind: leaf_node
            description: Accept IPv6 packets with zero UDP checksum
            valueless: true

      /flood-vtep:
        kind: leaf_node
        description: Replicate flooded traffic to this VTEP
        validators:
          mode: OR
          ipv4-address: {}
          ipv6-address: {}
        strip_kind: ip
        hints:
          address: Replicate flooded traffic to this VTEP
        multi: true

      /static-mac:
        kind: tag_node
        anchor: true
        description: Static remote MAC entry
        validators:
          mac: {}
        hints:
          mac-address: Remote unicast MAC
        children:
          remote:
            kind: leaf_node
            description: Unicast destination VTEP
            validators:
              mode: OR
              ipv4-address: {}
              ipv6-address: {}
            strip_kind: ip
            hints:
              address: Unicast destination VTEP
