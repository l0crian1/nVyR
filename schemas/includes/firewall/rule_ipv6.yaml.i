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
    - file: firewall/connection_ipv6.yaml.i
    - file: firewall/icmp-group-reference_ipv6.yaml.i
    - file: firewall/limit_ipv6.yaml.i
    - file: firewall/quota.yaml.i
    - file: firewall/add-to-group_ipv6.yaml.i
    - file: nftables/icmpv6-type.yaml.i
      add:
        /negatable: true
    - file: nftables/icmp-code.yaml.i
      add:
        /negatable: true
    - file: firewall/map-reference_ipv6.yaml.i
    - file: firewall/match-group-reference_ipv6.yaml.i
      add:
        /negatable: true
    - file: firewall/singleton-references_ipv6.yaml.i
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
        /depends: firewall-chain-ipv6
    - file: firewall/action.yaml.i
    - file: firewall/reject-response_ipv6.yaml.i

    source-address:
      kind: tag_node
      negatable: true
      strip_kind: ipv6
      description: Source IPv6 address or prefix
      validators:
        address: {version: 6}
      hints:
        x:x:x:x:x:x[/x]: Source IPv6 address or prefix
      children: # source-address

        mask:
          kind: leaf_node
          description: Bitmask selecting source IPv6 address bits to match
          validators:
            ipv6-address: {}
          hints:
            x:x:x:x:x:x: IPv6 bitmask; requires exactly one source address

    destination-address:
      kind: tag_node
      negatable: true
      strip_kind: ipv6
      description: Destination IPv6 address or prefix
      validators:
        address: {version: 6}
      hints:
        x:x:x:x:x:x[/x]: Destination IPv6 address or prefix
      children: # destination-address

        mask:
          kind: leaf_node
          description: Bitmask selecting destination IPv6 address bits to match
          validators:
            ipv6-address: {}
          hints:
            x:x:x:x:x:x: IPv6 bitmask; requires exactly one destination address
