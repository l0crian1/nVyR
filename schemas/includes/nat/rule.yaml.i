rule:
  kind: tag_node
  anchor: true
  description: Numbered IPv4 NAT rule
  validators:
    mode: AND
    integer-range: {minimum: 1, maximum: 999999}
    length: {maximum: 6}
  hints:
    1-999999: NAT rule number
  children: # rule

    include_schema:
    - file: firewall/map-reference_ipv4.yaml.i
    - file: firewall/match-group-reference_ipv4.yaml.i
    - file: firewall/singleton-references_ipv4.yaml.i
      as: null
    - file: nftables/common.yaml.i
      as: null

    source-address:
      kind: leaf_node
      strip_kind: ipv4
      description: Source IPv4 address or prefix
      validators:
        address: {version: 4}
      hints:
        x.x.x.x[/x]: Source IPv4 address or prefix
      multi: true

    destination-address:
      kind: leaf_node
      strip_kind: ipv4
      description: Destination IPv4 address or prefix
      validators:
        address: {version: 4}
      hints:
        x.x.x.x[/x]: Destination IPv4 address or prefix
      multi: true

    translation:
      kind: node
      description: NAT translation settings
      children: # translation

        address:
          kind: leaf_node
          strip_kind: ipv4
          description: Translation IPv4 address or inclusive address pool
          validators:
            mode: OR
            ipv4-address: {}
            network: {version: 4}
            ip-range: {version: 4}
          hints:
            x.x.x.x: Single IPv4 address
            x.x.x.x/x: IPv4 network used as an inclusive address pool
            start-end: Inclusive ascending IPv4 address range

        port:
          kind: leaf_node
          description: Translation port or inclusive port range
          validators:
            port: {allow_range: true}
          hints:
            1-65535: Translation port
            start-end: Inclusive ascending translation port range

        port-mapping:
          kind: leaf_node
          description: Transport port selection behavior
          choices:
            default: Use the kernel's default port selection
            random: Randomize port selection
            fully-random: Fully randomize port selection
          validators:
            list: {values: default random fully-random}

        persistent:
          kind: leaf_node
          description: Keep translated address selection stable for a client across connections
          valueless: true

    exclude:
      kind: leaf_node
      description: Return without translation; skip later nVyR rules in this NAT chain
      valueless: true
