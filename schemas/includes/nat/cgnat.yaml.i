cgnat:
  kind: node
  description: Deterministic IPv4 carrier-grade NAT allocations
  children:

    pool:
      kind: tag_node
      anchor: true
      dependency: cgnat-pool
      description: Public addresses and per-subscriber port blocks
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: CGN pool name
      children:

        public-address:
          kind: leaf_node
          multi: true
          strip_kind: ipv4
          description: Public IPv4 address, network or inclusive range
          validators:
            mode: OR
            ipv4-address: {}
            network: {version: 4}
            ip-range: {version: 4}
          hints:
            x.x.x.x[/x]: Public IPv4 address or network
            start-end: Inclusive ascending public IPv4 range

        port-range:
          kind: leaf_node
          description: Usable translated ports and ICMP identifiers
          validators:
            port: {allow_range: true}
          hints:
            start-end: Inclusive port range; incomplete final blocks remain unused
          default: {mode: direct, value: '1024-65535'}

        block-size:
          kind: leaf_node
          description: Ports allocated to each subscriber on one public address
          validators:
            integer-range: {minimum: 1, maximum: 65535}
          hints:
            1-65535: Number of ports per subscriber; not a connection limit
          default: {mode: direct, value: '1024'}

        description:
          kind: leaf_node
          description: Description of the public address pool
          validators:
            text: {}
          hints:
            text: Description; quote spaces

    rule:
      kind: tag_node
      anchor: true
      description: Ordered subscriber translation policy after ordinary source NAT
      validators:
        mode: AND
        integer-range: {minimum: 1, maximum: 999999}
        length: {maximum: 6}
      hints:
        1-999999: CGN policy number
      children:

        include_schema:
        - file: nftables/common.yaml.i
          as: null
          remove:
          - /protocol
          add:
            /inbound-interface/negatable: true
            /outbound-interface/negatable: true
            /source-port/negatable: true
            /destination-port/negatable: true
        - file: firewall/match-group-reference_ipv4.yaml.i
          add:
            /negatable: true
        - file: firewall/singleton-references_ipv4.yaml.i
          as: null
          remove:
          - /source-domain-group
          - /source-mac-group
          - /destination-mac-group
          add:
            /destination-address-group/negatable: true
            /destination-domain-group/negatable: true
            /inbound-interface-group/negatable: true
            /outbound-interface-group/negatable: true
            /source-port-group/negatable: true
            /destination-port-group/negatable: true

        source-address:
          kind: leaf_node
          multi: true
          strip_kind: ipv4
          description: Stable subscriber IPv4 addresses receiving ordered allocations
          validators:
            mode: OR
            address: {version: 4}
            ip-range: {version: 4}
          hints:
            x.x.x.x[/x]: Subscriber IPv4 address or prefix
            start-end: Inclusive subscriber range

        destination-address:
          kind: leaf_node
          multi: true
          negatable: true
          strip_kind: ipv4
          description: Destination IPv4 address, prefix or range
          validators:
            mode: OR
            address: {version: 4}
            ip-range: {version: 4}
          hints:
            x.x.x.x[/x]: Destination IPv4 address or prefix
            start-end: Inclusive destination range

        protocol:
          kind: leaf_node
          multi: true
          negatable: true
          description: Protocol to translate; omission permits TCP, UDP and ICMP
          validators:
            list: {values: tcp udp icmp}
          choices:
            tcp: Transmission Control Protocol
            udp: User Datagram Protocol
            icmp: Internet Control Message Protocol; translate echo identifiers

        packet-mark:
          kind: leaf_node
          multi: true
          negatable: true
          description: Match the packet mark
          validators:
            integer-range: {minimum: 0, maximum: 4294967295, allow_range: true}
          hints:
            0-4294967295: Packet mark or inclusive range

        connection:
          kind: node
          anchor: true
          description: Match tracked connection metadata
          children:

            mark:
              kind: leaf_node
              multi: true
              negatable: true
              description: Match the tracked connection mark
              validators:
                integer-range: {minimum: 0, maximum: 4294967295, allow_range: true}
              hints:
                0-4294967295: Connection mark or inclusive range

        pool:
          kind: leaf_node
          depends: cgnat-pool
          description: Public address pool used for subscriber allocations
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Configured CGN pool
          suggestors:
            config-path: {path: 'nat cgnat pool'}

        allocation-offset:
          kind: leaf_node
          description: First subscriber block index in the pool; counts blocks, not ports
          validators:
            integer-range: {minimum: 0, maximum: 281474976710655}
          hints:
            number: Zero-based block offset; reserve separate slots for other subscribers
          default: {mode: direct, value: '0'}

        vrf:
          kind: leaf_node
          depends: vrf
          description: Subscriber and external-interface VRF; omission selects default
          validators:
            regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
          hints:
            name: Configured VRF or default
          suggestors:
            config-path: {path: 'vrf name'}
          choices:
            default: Default routing instance

        port-mapping:
          kind: leaf_node
          description: Native translated port and identifier selection
          validators:
            list: {values: default random fully-random}
          choices:
            default: Preserve native kernel allocation behavior
            random: Randomize native port selection
            fully-random: Fully randomize native port selection

