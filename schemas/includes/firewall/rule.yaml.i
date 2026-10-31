rule:
  kind: tag_node
  anchor: true
  description: Numbered firewall rule
  validators:
    mode: AND
    integer-range: {minimum: 1, maximum: 999999}
    length: {maximum: 6}
  hints:
    1-999999: Firewall rule number
  children: # rule

    include_schema:
    - file: firewall/modify.yaml.i
    - file: firewall/connection_ipv4.yaml.i
    - file: firewall/icmp-group-reference_ipv4.yaml.i
    - file: firewall/limit_ipv4.yaml.i
    - file: firewall/quota.yaml.i
    - file: firewall/add-to-group_ipv4.yaml.i
    - file: nftables/icmp-type.yaml.i
      add:
        /negatable: true
    - file: nftables/icmp-code.yaml.i
      add:
        /negatable: true
    - file: firewall/map-reference_ipv4.yaml.i
    - file: firewall/match-group-reference_ipv4.yaml.i
      add:
        /negatable: true
    - file: firewall/singleton-references_ipv4.yaml.i
      as: null
      add:
        /inbound-interface-group/negatable: true
        /outbound-interface-group/negatable: true
        /source-mac-group/negatable: true
        /destination-mac-group/negatable: true
        /source-port-group/negatable: true
        /destination-port-group/negatable: true
        /source-domain-group/negatable: true
        /destination-domain-group/negatable: true
        /source-address-group/negatable: true
        /destination-address-group/negatable: true
    - file: firewall/matches.yaml.i
      as: null
    - file: nftables/common.yaml.i
      as: null
      add:
        /protocol/negatable: true
        /source-port/negatable: true
        /destination-port/negatable: true
        /inbound-interface/negatable: true
        /inbound-interface/reapply-on-change: [vrf]
        /outbound-interface/negatable: true
      replace:
        /disable/description: Disable this firewall rule
    - file: firewall/jump-target.yaml.i
      add:
        /depends: firewall-chain-ipv4
    - file: firewall/action.yaml.i
    - file: firewall/reject-response_ipv4.yaml.i

    source-address:
      kind: tag_node
      negatable: true
      strip_kind: ipv4
      description: Source IPv4 address or prefix
      validators:
        address: {version: 4}
      hints:
        x.x.x.x[/x]: Source IPv4 address or prefix
      children: # source-address

        mask:
          kind: leaf_node
          description: Bitmask selecting source IPv4 address bits to match
          validators:
            ipv4-address: {}
          hints:
            x.x.x.x: IPv4 bitmask; requires exactly one source address

    destination-address:
      kind: tag_node
      negatable: true
      strip_kind: ipv4
      description: Destination IPv4 address or prefix
      validators:
        address: {version: 4}
      hints:
        x.x.x.x[/x]: Destination IPv4 address or prefix
      children: # destination-address

        mask:
          kind: leaf_node
          description: Bitmask selecting destination IPv4 address bits to match
          validators:
            ipv4-address: {}
          hints:
            x.x.x.x: IPv4 bitmask; requires exactly one destination address
