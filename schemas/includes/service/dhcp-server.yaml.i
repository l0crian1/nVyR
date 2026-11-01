dhcp-server:
  kind: node
  description: DHCPv4 server managed by Kea
  script:
    name: dhcp-server
    priority: 55
    register:
      vrf: default

    watch:
    - interfaces
    - system logging
  children:

    include_schema:
    - file: service/dhcp-ha.yaml.i
    - file: service/dhcp4-scope.yaml.i
      as: null

      add:
        /lease-time/default:
          mode: direct
          value: 1d

    socket-type:
      kind: leaf_node
      description: Socket type for all DHCPv4 listeners in this routing instance
      choices:
        raw: Receive direct broadcasts and relayed requests on the listening interface
        udp: Receive relayed requests through normal IP routing; no direct broadcasts
      validators:
        list: {values: raw udp}
      default:
        mode: direct
        value: raw

    update-hostfile:
      kind: leaf_node
      description: Publish active DHCPv4 lease hostnames in the local hosts file
      valueless: true

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
        x.x.x.x: Local listening address resolved within this routing instance (IPv4)
      validators:
        ipv4-address: {}
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
        - file: service/dhcp4-scope.yaml.i
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
              version: 4
          hints:
            prefix: IPv4 network prefix without host bits
          children:

            include_schema:
            - file: service/dhcp4-scope.yaml.i
              as: null

            range:
              kind: leaf_node
              description: Inclusive dynamic allocation range; repeat for disjoint ranges
              validators:
                ip-range:
                  version: 4
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
                    x.x.x.x: Reserved client address (IPv4)
                  validators:
                    ipv4-address: {}

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

                mac-address:
                  kind: leaf_node
                  description: Client Ethernet MAC address
                  hints:
                    xx:xx:xx:xx:xx:xx: Client Ethernet MAC address
                  validators:
                    mac: {}

                client-id:
                  kind: leaf_node
                  description: Client identifier as colon-separated hexadecimal bytes
                  hints:
                    hex-bytes: Client identifier as colon-separated hexadecimal bytes (2-255 bytes)
                  validators:
                    dhcp-identifier:
                      minimum: 2
                      maximum: 255
