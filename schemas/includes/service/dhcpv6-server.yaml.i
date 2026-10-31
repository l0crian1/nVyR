dhcpv6-server:
  kind: node
  description: DHCPv6 server managed by Kea
  script:
    name: dhcpv6-server
    priority: 55
    register:
      vrf: default

    watch:
    - interfaces
    - system logging
  children:

    include_schema:
    - file: service/dhcp-ha.yaml.i
      replace:
        /children/port/default/value: '8006'
        /children/peer/children/port/default/value: '8006'
    - file: service/dhcp6-scope.yaml.i
      as: null

      add:
        /preferred-lifetime/default:
          mode: direct
          value: 12h

        /valid-lifetime/default:
          mode: direct
          value: 1d

    listen-interface:
      kind: leaf_node
      description: Listen on this interface; cannot overlap a listen-address selection
      hints:
        interface: Interface name in this routing instance; for example eth1
      validators:
        regex:
          pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'
      depends: interface

      reapply-on-change:
      - address
      - vrf
      - disable

      suggestors:
        interfaces: {}
      multi: true

    listen-address:
      kind: leaf_node
      description: Local listening address resolved within this routing instance
      hints:
        IPv6-address: Local listening address resolved within this routing instance (IPv6)
      validators:
        dhcpv6-listen-address: {}
      multi: true

    shared-network:
      kind: tag_node
      description: Named shared link containing one or more subnets
      validators:
        regex:
          pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'
      hints:
        name: Shared-network name
      children:

        include_schema:
        - file: service/dhcp6-scope.yaml.i
          as: null

        interface:
          kind: leaf_node
          description: Interface used to receive directly connected client requests
          hints:
            interface: Interface name in this routing instance; for example eth1
          validators:
            regex:
              pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'
          depends: interface

          reapply-on-change:
          - address
          - vrf
          - disable

          suggestors:
            interfaces: {}

        subnet:
          kind: tag_node
          description: Client subnet on this shared link
          validators:
            network:
              version: 6
          hints:
            prefix: IPv6 network prefix without host bits
          children:

            include_schema:
            - file: service/dhcp6-scope.yaml.i
              as: null

            range:
              kind: leaf_node
              description: Inclusive dynamic allocation range; repeat for disjoint ranges
              validators:
                ip-range:
                  version: 6
              multi: true
              hints:
                start-end: First and last address separated by a hyphen

            reservation:
              kind: tag_node
              anchor: true
              description: Named client reservation
              validators:
                regex:
                  pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'
              hints:
                name: Reservation name
              children:

                address:
                  kind: leaf_node
                  description: Reserved client address
                  hints:
                    IPv6-address: Reserved client address (IPv6)
                  validators:
                    ipv6-address: {}

                hostname:
                  kind: leaf_node
                  description: Reserved client hostname
                  hints:
                    hostname: Reserved client hostname; for example printer.home.example
                  validators:
                    dhcp-domain: {}

                description:
                  kind: leaf_node
                  description: Administrative description
                  hints:
                    text: Administrative description; quote spaces; at most 255 characters
                  validators:
                    length:
                      maximum: 255

                duid:
                  kind: leaf_node
                  description: DHCP unique identifier as colon-separated hexadecimal bytes
                  hints:
                    hex-bytes: DHCP unique identifier as colon-separated hexadecimal bytes (3-130 bytes)
                  validators:
                    dhcp-identifier:
                      minimum: 3
                      maximum: 130
