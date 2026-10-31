group:
  kind: node
  description: Reusable firewall groups
  children: # group

    include_schema:
    - file: firewall/interface-group.yaml.i
    - file: firewall/mac-group.yaml.i
    - file: firewall/port-group.yaml.i
    - file: firewall/counter-group.yaml.i
    - file: firewall/quota-group.yaml.i
    - file: firewall/log-group.yaml.i

    map:
      kind: node
      description: Named packet-field lookup maps
      children: # map

        include_schema:
        - file: firewall/map_ipv4.yaml.i
        - file: firewall/map_ipv6.yaml.i
        - file: firewall/map_inet.yaml.i

    match-group:
      kind: node
      description: Named collections of packet-field combinations
      children: # match-group

        include_schema:
        - file: firewall/match-group_ipv4.yaml.i
        - file: firewall/match-group_ipv6.yaml.i
        - file: firewall/match-group_inet.yaml.i

    address-group:
      kind: node
      description: Named IP address groups
      children: # address-group

        include_schema:
        - file: firewall/address-group_ipv4.yaml.i
        - file: firewall/address-group_ipv6.yaml.i

    domain-group:
      kind: node
      description: IP address sets populated from DNS names
      children:

        include_schema:
        - file: firewall/domain-group_ipv4.yaml.i
        - file: firewall/domain-group_ipv6.yaml.i

    timeout-group:
      kind: node
      description: Named connection tracking timeout policies
      children:

        include_schema:
        - file: firewall/timeout-group_ipv4.yaml.i
        - file: firewall/timeout-group_ipv6.yaml.i
        - file: firewall/timeout-group_inet.yaml.i

    limit-group:
      kind: node
      description: Shared rate allowances
      children: # limit-group

        include_schema:
        - file: firewall/limit-group_ipv4.yaml.i
        - file: firewall/limit-group_ipv6.yaml.i
        - file: firewall/limit-group_inet.yaml.i

    icmp-group:
      kind: node
      description: Named ICMP type and type/code groups
      children: # icmp-group

        include_schema:
        - file: firewall/icmp-group_ipv4.yaml.i
        - file: firewall/icmp-group_ipv6.yaml.i
