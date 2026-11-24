macsec:
  kind: tag_node
  dependency: interface
  anchor: true
  description: MACsec Ethernet interface using MKA
  validators:
    regex: {pattern: 'macsec[0-9]{1,9}'}
  hints:
    macsecN: MACsec interface name
  suggestors:
    interfaces: {prefix: macsec}
  script:
    name: macsec
    priority: 11
  include_schema:
  - file: interfaces/common.yaml.i
    remove:
    - /mac
    - /mtu/default
    replace:
      /address/validators:
        ip-interface: {}
    add:

      /source-interface:
        kind: leaf_node
        description: Underlying Ethernet link carrying MKA and MACsec frames
        validators:
          regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
        depends: interface
        suggestors:
          interfaces: {}
        hints:
          interface: Parent interface

      /sci-port:
        kind: leaf_node
        description: Port component of the local secure channel identifier (default 1)
        validators:
          integer-range: {minimum: 1, maximum: 65534}
        hints:
          1-65534: SCI port

      /transmit-mode:
        kind: leaf_node
        description: Protection applied to transmitted frames
        choices:
          encrypt: Authenticate and encrypt (default)
          integrity-only: Authenticate without encrypting
        validators:
          list: {values: 'encrypt integrity-only'}

      /replay-protection:
        kind: node
        description: Check receive packet numbers (strict ordering unless a window is set)
        children:

          window:
            kind: leaf_node
            description: Number of packets of reordering tolerated
            validators:
              integer-range: {minimum: 0, maximum: 4294967295}
            hints:
              0-4294967295: Replay window in packets

      /mka:
        kind: node
        anchor: true
        description: MACsec Key Agreement
        children:

          key-server-priority:
            kind: leaf_node
            description: Key server election priority (lower wins)
            validators:
              integer-range: {minimum: 0, maximum: 255}
            hints:
              0-255: Election priority

          preshared-key:
            kind: node
            anchor: true
            description: Pre-shared connectivity association
            children:

              cak:
                kind: leaf_node
                secret: true
                description: Connectivity association key
                validators:
                  regex: {pattern: '(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})'}
                hints:
                  hex: 16 or 32 bytes in hex

              ckn:
                kind: leaf_node
                description: Connectivity association key name
                validators:
                  regex: {pattern: '(?:[a-fA-F0-9]{2}){1,32}'}
                hints:
                  hex: 1 to 32 bytes in hex
