bridge:
  kind: tag_node
  anchor: true
  dependency: interface
  description: Linux bridge interface

  validators:
    regex:
      pattern: br[0-9]+

  hints:
    brN: Bridge interface name

  script:
    name: bridge
    priority: 12
    watch:
    - interfaces

  include_schema:
  - file: interfaces/common.yaml.i
    replace:

      /address:
        include_schema:
        - file: interfaces/address_dhcp.yaml.i
          as: null
    add:

      /dhcp-options:
        include_schema:
        - file: interfaces/dhcp-options.yaml.i
          as: null

      /member:
        kind: node
        anchor: true
        description: Bridge membership
        children:

          interface:
            kind: tag_node
            anchor: true
            description: Bridge member interface
            validators:
              regex:
                pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'
            hints:
              interface: Bridge member interface
            children:

              learning:
                kind: node
                anchor: true
                description: MAC learning
                children:

                  disable:
                    kind: leaf_node
                    valueless: true
                    description: Disable MAC learning

              hairpin:
                kind: leaf_node
                valueless: true
                description: Allow forwarding back through this port

              isolated:
                kind: leaf_node
                valueless: true
                description: Prevent communication with other isolated ports

              locked:
                kind: leaf_node
                valueless: true
                description: Require an authorized source MAC forwarding entry

              backup-interface:
                kind: leaf_node
                description: Redirect egress to this member when carrier is lost
                validators:
                  regex:
                    pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'
                hints:
                  interface: Redirect egress to this member when carrier is lost
                depends: interface
                suggestors:
                  interfaces: {}

              flood:
                kind: node
                anchor: true
                description: Unknown destination and broadcast flooding
                children:

                  unknown-unicast:
                    kind: node
                    anchor: true
                    description: Unknown unicast flooding
                    children:

                      disable:
                        kind: leaf_node
                        valueless: true
                        description: Disable unknown unicast flooding

                  unknown-multicast:
                    kind: node
                    anchor: true
                    description: Unknown multicast flooding
                    children:

                      disable:
                        kind: leaf_node
                        valueless: true
                        description: Disable unknown multicast flooding

                  broadcast:
                    kind: node
                    anchor: true
                    description: Broadcast flooding
                    children:

                      disable:
                        kind: leaf_node
                        valueless: true
                        description: Disable broadcast flooding

              spanning-tree:
                kind: node
                anchor: true
                description: Port spanning-tree settings
                children:

                  cost:
                    kind: leaf_node
                    description: STP path cost
                    validators:
                      integer-range:
                        minimum: 1
                        maximum: 65535
                    hints:
                      1-65535: STP path cost

                  priority:
                    kind: leaf_node
                    description: STP port priority
                    validators:
                      integer-range:
                        minimum: 0
                        maximum: 63
                    hints:
                      0-63: STP port priority

                  bpdu-guard:
                    kind: leaf_node
                    valueless: true
                    description: Block this port if an STP BPDU is received

                  root-guard:
                    kind: leaf_node
                    valueless: true
                    description: Prevent this port from becoming the root port

              multicast:
                kind: node
                anchor: true
                description: Port multicast settings
                children:

                  router:
                    kind: leaf_node
                    description: Multicast router port selection
                    validators:
                      list:
                        values: disabled auto permanent
                    choices:
                      disabled: Never a multicast router port
                      auto: Detect multicast routers from queries
                      permanent: Always forward multicast toward this port

                  fast-leave:
                    kind: leaf_node
                    valueless: true
                    description: Immediately remove membership on a leave

                  to-unicast:
                    kind: leaf_node
                    valueless: true
                    description: Replicate multicast as unicast for known listeners

                  maximum-groups:
                    kind: leaf_node
                    description: Maximum multicast memberships; zero is unlimited
                    validators:
                      integer-range:
                        minimum: 0
                        maximum: 4294967295
                    hints:
                      0-4294967295: Maximum multicast memberships; zero is unlimited

              neighbor-suppression:
                kind: leaf_node
                valueless: true
                description: Suppress ARP and ND

              neighbor-vlan-suppression:
                kind: leaf_node
                valueless: true
                description: Use per-VLAN ARP and ND suppression

              link-local-forward:
                kind: leaf_node
                description: Forward selected link-local protocols
                validators:
                  list:
                    values: lldp eapol
                choices:
                  lldp: Forward LLDP frames
                  eapol: Forward EAPOL frames
                multi: true

              vlan:
                kind: tag_node
                anchor: true
                description: VLAN membership and settings
                validators:
                  mode: AND
                  integer-range:
                    minimum: 1
                    maximum: 4094
                  regex:
                    pattern: '[1-9][0-9]{0,3}'
                hints:
                  1-4094: VLAN membership and settings
                children:

                  pvid:
                    kind: leaf_node
                    valueless: true
                    description: Classify untagged ingress into this VLAN

                  untagged:
                    kind: leaf_node
                    valueless: true
                    description: Remove the VLAN tag on egress

                  multicast:
                    kind: node
                    anchor: true
                    description: Per-VLAN port multicast settings
                    children:

                      router:
                        kind: leaf_node
                        description: Multicast router port selection
                        validators:
                          list:
                            values: disabled auto permanent
                        choices:
                          disabled: Never a multicast router port
                          auto: Detect multicast routers from queries
                          permanent: Always forward multicast toward this port

                      maximum-groups:
                        kind: leaf_node
                        description: Maximum multicast memberships; zero is unlimited
                        validators:
                          integer-range:
                            minimum: 0
                            maximum: 4294967295
                        hints:
                          0-4294967295: Maximum multicast memberships; zero is unlimited

                  neighbor-suppression:
                    kind: leaf_node
                    valueless: true
                    description: Suppress ARP and ND in this VLAN
            depends: interface
            suggestors:
              interfaces: {}

      /mac-learning:
        kind: node
        anchor: true
        description: Forwarding database learning
        children:

          ageing-time:
            kind: leaf_node
            description: MAC retention time; zero never ages
            validators:
              mode: OR
              duration:
                maximum: 42949672
              list:
                values: 0s
            hints:
              duration: Time in s, m, h or d

          maximum-entries:
            kind: leaf_node
            description: Maximum learned MAC entries; zero is unlimited
            validators:
              integer-range:
                minimum: 0
                maximum: 4294967295
            hints:
              0-4294967295: Maximum learned MAC entries; zero is unlimited

          link-local:
            kind: node
            anchor: true
            description: Learning from link-local frames
            children:

              disable:
                kind: leaf_node
                valueless: true
                description: Disable learning from link-local frames

      /static-mac:
        kind: tag_node
        anchor: true
        description: Static unicast forwarding entry
        validators:
          mac: {}
        hints:
          mac-address: Static unicast forwarding entry
        children:

          interface:
            kind: leaf_node
            description: Output bridge member
            validators:
              regex:
                pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'
            hints:
              interface: Output bridge member
            depends: interface
            suggestors:
              interfaces: {}

          vlan:
            kind: tag_node
            anchor: true
            description: VLAN membership and settings
            validators:
              mode: AND
              integer-range:
                minimum: 1
                maximum: 4094
              regex:
                pattern: '[1-9][0-9]{0,3}'
            hints:
              1-4094: VLAN membership and settings
            children:

              interface:
                kind: leaf_node
                description: Output bridge member
                validators:
                  regex:
                    pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'
                hints:
                  interface: Output bridge member
                depends: interface
                suggestors:
                  interfaces: {}

      /spanning-tree:
        kind: node
        anchor: true
        description: Enable spanning tree and configure its parameters
        children:

          priority:
            kind: leaf_node
            description: STP bridge priority
            validators:
              integer-range:
                minimum: 0
                maximum: 65535
            hints:
              0-65535: STP bridge priority

          hello-time:
            kind: leaf_node
            description: STP hello interval (1-10 seconds)
            validators:
              duration:
                maximum: 10
            hints:
              duration: STP hello time in seconds (1-10); for example 1s

          forward-delay:
            kind: leaf_node
            description: STP forwarding delay (2-30 seconds)
            validators:
              kernel-duration:
                minimum: 2
                maximum: 30
            hints:
              duration: STP forward delay in seconds (2-30); for example 2s

          max-age:
            kind: leaf_node
            description: STP maximum age (6-40 seconds)
            validators:
              kernel-duration:
                minimum: 6
                maximum: 40
            hints:
              duration: STP max age in seconds (6-40); for example 6s

      /vlan-filtering:
        kind: leaf_node
        valueless: true
        description: Filter switched traffic by VLAN membership

      /vlan-protocol:
        kind: leaf_node
        description: VLAN tag protocol
        validators:
          list:
            values: 802.1q 802.1ad
        choices:
          802.1q: 802.1Q customer VLAN tags
          802.1ad: 802.1ad service VLAN tags

      /default-pvid:
        kind: leaf_node
        description: Implicit untagged VLAN; zero disables automatic VLAN 1
        validators:
          integer-range:
            minimum: 0
            maximum: 4094
        hints:
          0-4094: Implicit untagged VLAN; zero disables automatic VLAN 1

      /vlan-statistics:
        kind: leaf_node
        valueless: true
        description: Collect per-VLAN counters

      /vlan-statistics-per-port:
        kind: leaf_node
        valueless: true
        description: Collect separate per-port VLAN counters

      /vlan:
        kind: tag_node
        anchor: true
        description: VLAN membership and settings
        validators:
          mode: AND
          integer-range:
            minimum: 1
            maximum: 4094
          regex:
            pattern: '[1-9][0-9]{0,3}'
        hints:
          1-4094: VLAN membership and settings
        children:

          local:
            kind: node
            anchor: true
            description: Include the router bridge interface in this VLAN
            children:

              pvid:
                kind: leaf_node
                valueless: true
                description: Classify local untagged traffic into this VLAN

              untagged:
                kind: leaf_node
                valueless: true
                description: Deliver this VLAN untagged locally

          multicast:
            kind: node
            anchor: true
            description: Per-VLAN multicast settings
            children:

              snooping:
                kind: node
                anchor: true
                description: Multicast snooping
                children:

                  disable:
                    kind: leaf_node
                    valueless: true
                    description: Disable multicast snooping

              querier:
                kind: leaf_node
                valueless: true
                description: Send multicast membership queries

              igmp-version:
                kind: leaf_node
                description: IGMP query version
                validators:
                  integer-range:
                    minimum: 2
                    maximum: 3
                hints:
                  2-3: IGMP query version

              mld-version:
                kind: leaf_node
                description: MLD query version
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 2
                hints:
                  1-2: MLD query version

              last-member-count:
                kind: leaf_node
                description: Queries sent before removing a departed multicast listener
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 255
                hints:
                  1-255: Queries sent before removing a departed multicast listener

              startup-query-count:
                kind: leaf_node
                description: Membership queries sent when the multicast querier starts
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 255
                hints:
                  1-255: Membership queries sent when the multicast querier starts

              last-member-interval:
                kind: leaf_node
                description: Interval between queries checking a departed multicast listener
                validators:
                  duration:
                    maximum: 42949672
                hints:
                  duration: Interval between queries checking a departed multicast listener; use s, m, h or d

              startup-query-interval:
                kind: leaf_node
                description: Interval between initial multicast membership queries
                validators:
                  duration:
                    maximum: 42949672
                hints:
                  duration: Interval between initial multicast membership queries; use s, m, h or d

              membership-interval:
                kind: leaf_node
                description: Lifetime of multicast membership without a listener report
                validators:
                  duration:
                    maximum: 42949672
                hints:
                  duration: Lifetime of multicast membership without a listener report; use s, m, h or d

              querier-interval:
                kind: leaf_node
                description: Time before an inactive multicast querier is considered absent
                validators:
                  duration:
                    maximum: 42949672
                hints:
                  duration: Time before an inactive multicast querier is considered absent; use s, m, h or d

              query-interval:
                kind: leaf_node
                description: Interval between regular multicast membership queries
                validators:
                  duration:
                    maximum: 42949672
                hints:
                  duration: Interval between regular multicast membership queries; use s, m, h or d

              query-response-interval:
                kind: leaf_node
                description: Maximum response time advertised in multicast queries
                validators:
                  duration:
                    maximum: 42949672
                hints:
                  duration: Maximum response time advertised in multicast queries; use s, m, h or d

      /multicast:
        kind: node
        anchor: true
        description: Multicast snooping and membership
        children:

          snooping:
            kind: node
            anchor: true
            description: Multicast snooping
            children:

              disable:
                kind: leaf_node
                valueless: true
                description: Disable multicast snooping

          querier:
            kind: leaf_node
            valueless: true
            description: Send multicast membership queries

          igmp-version:
            kind: leaf_node
            description: IGMP query version
            validators:
              integer-range:
                minimum: 2
                maximum: 3
            hints:
              2-3: IGMP query version

          mld-version:
            kind: leaf_node
            description: MLD query version
            validators:
              integer-range:
                minimum: 1
                maximum: 2
            hints:
              1-2: MLD query version

          last-member-count:
            kind: leaf_node
            description: Queries sent before removing a departed multicast listener
            validators:
              integer-range:
                minimum: 1
                maximum: 255
            hints:
              1-255: Queries sent before removing a departed multicast listener

          startup-query-count:
            kind: leaf_node
            description: Membership queries sent when the multicast querier starts
            validators:
              integer-range:
                minimum: 1
                maximum: 255
            hints:
              1-255: Membership queries sent when the multicast querier starts

          last-member-interval:
            kind: leaf_node
            description: Interval between queries checking a departed multicast listener
            validators:
              duration:
                maximum: 42949672
            hints:
              duration: Interval between queries checking a departed multicast listener; use s, m, h or d

          startup-query-interval:
            kind: leaf_node
            description: Interval between initial multicast membership queries
            validators:
              duration:
                maximum: 42949672
            hints:
              duration: Interval between initial multicast membership queries; use s, m, h or d

          membership-interval:
            kind: leaf_node
            description: Lifetime of multicast membership without a listener report
            validators:
              duration:
                maximum: 42949672
            hints:
              duration: Lifetime of multicast membership without a listener report; use s, m, h or d

          querier-interval:
            kind: leaf_node
            description: Time before an inactive multicast querier is considered absent
            validators:
              duration:
                maximum: 42949672
            hints:
              duration: Time before an inactive multicast querier is considered absent; use s, m, h or d

          query-interval:
            kind: leaf_node
            description: Interval between regular multicast membership queries
            validators:
              duration:
                maximum: 42949672
            hints:
              duration: Interval between regular multicast membership queries; use s, m, h or d

          query-response-interval:
            kind: leaf_node
            description: Maximum response time advertised in multicast queries
            validators:
              duration:
                maximum: 42949672
            hints:
              duration: Maximum response time advertised in multicast queries; use s, m, h or d

          vlan-snooping:
            kind: leaf_node
            valueless: true
            description: Maintain separate multicast contexts per VLAN

          query-use-interface-address:
            kind: leaf_node
            valueless: true
            description: Use the bridge IPv4 address for IGMP queries

          router:
            kind: leaf_node
            description: Multicast router port selection
            validators:
              list:
                values: disabled auto permanent
            choices:
              disabled: Never a multicast router port
              auto: Detect multicast routers from queries
              permanent: Always forward multicast toward this port

          statistics:
            kind: leaf_node
            valueless: true
            description: Collect multicast protocol statistics

          static-group:
            kind: tag_node
            anchor: true
            description: Configured multicast membership
            validators:
              regex:
                pattern: '[a-zA-Z][a-zA-Z0-9_-]{0,62}'
            hints:
              name: Configured multicast membership
            children:

              address:
                kind: leaf_node
                description: IPv4 or IPv6 multicast group address
                validators:
                  multicast-address: {}
                hints:
                  address: Multicast group address

              interface:
                kind: leaf_node
                description: Receiving bridge member
                validators:
                  regex:
                    pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'
                hints:
                  interface: Receiving bridge member
                depends: interface
                suggestors:
                  interfaces: {}
                multi: true

              vlan:
                kind: leaf_node
                description: VLAN identifier
                validators:
                  integer-range:
                    minimum: 1
                    maximum: 4094
                hints:
                  1-4094: VLAN identifier

              source:
                kind: leaf_node
                description: Unicast source for source-specific membership
                validators:
                  unicast-address: {}
                hints:
                  address: Source address

      /link-local-forward:
        kind: leaf_node
        description: Forward selected link-local protocols
        validators:
          list:
            values: lldp eapol
        choices:
          lldp: Forward LLDP frames
          eapol: Forward EAPOL frames
        multi: true

      /vif:
        include_schema:
        - file: interfaces/vif.yaml.i
          as: null
