rule:
  kind: tag_node
  anchor: true
  description: Numbered IPv6 NAT rule
  validators:
    mode: AND
    integer-range: {minimum: 1, maximum: 999999}
    length: {maximum: 6}
  hints:
    1-999999: NAT rule number
  children: # rule

    include_schema:
    - file: firewall/map-reference_ipv6.yaml.i
    - file: firewall/match-group-reference_ipv6.yaml.i
    - file: firewall/singleton-references_ipv6.yaml.i
      as: null
    - file: nftables/common.yaml.i
      as: null

    source-address:
      kind: leaf_node
      strip_kind: ipv6
      description: Source IPv6 address or prefix
      validators:
        address: {version: 6}
      hints:
        h:h:h:h:h:h:h:h[/x]: Source IPv6 address or prefix
      multi: true

    destination-address:
      kind: leaf_node
      strip_kind: ipv6
      description: Destination IPv6 address or prefix
      validators:
        address: {version: 6}
      hints:
        h:h:h:h:h:h:h:h[/x]: Destination IPv6 address or prefix
      multi: true

    translation:
      kind: node
      description: NAT translation settings
      children: # translation

        address:
          kind: leaf_node
          strip_kind: ipv6
          description: Translation IPv6 address or inclusive address pool
          validators:
            mode: OR
            ipv6-address: {}
            network: {version: 6}
            ip-range: {version: 6}
          hints:
            h:h:h:h:h:h:h:h: Single IPv6 address
            h:h:h:h:h:h:h:h/x: IPv6 network used as an inclusive address pool
            start-end: Inclusive ascending IPv6 address range

        include_schema:
        - file: nat/translation-options.yaml.i
          as: null

    exclude:
      kind: leaf_node
      description: Return without translation; skip later nVyR rules in this NAT chain
      valueless: true
