children: # group options

  include_schema:
  - file: firewall/group-description.yaml.i
  - file: nftables/counter.yaml.i
  - file: nftables/last-used.yaml.i

  match:
    kind: node
    anchor: true
    description: Packet fields included in this group's lookup key
    children: # match

      include_schema:
      - file: firewall/connection-match.yaml.i

      tcp-flags:
        kind: leaf_node
        description: Match TCP flag requirements
        valueless: true

      packet-type:
        kind: leaf_node
        description: Match packet type
        valueless: true

      inbound-link-group:
        kind: leaf_node
        valueless: true
        description: Match inbound Linux interface link group

      inbound-interface:
        kind: leaf_node
        description: Match inbound interface
        valueless: true

      outbound-link-group:
        kind: leaf_node
        valueless: true
        description: Match outbound Linux interface link group

      outbound-interface:
        kind: leaf_node
        description: Match outbound interface
        valueless: true

      source-mac:
        kind: leaf_node
        description: Match source MAC
        valueless: true

      destination-mac:
        kind: leaf_node
        description: Match destination MAC
        valueless: true

      source-address:
        kind: leaf_node
        description: Match source address
        valueless: true

      destination-address:
        kind: leaf_node
        description: Match destination address
        valueless: true

      packet-mark:
        kind: leaf_node
        description: Match packet mark
        valueless: true

      dscp:
        kind: leaf_node
        description: Match DSCP
        valueless: true

      protocol:
        kind: leaf_node
        description: Match protocol
        valueless: true

      icmp-type:
        kind: leaf_node
        description: Match ICMP type
        valueless: true

      icmp-code:
        kind: leaf_node
        description: Match ICMP code
        valueless: true

      source-port:
        kind: leaf_node
        description: Match source port
        valueless: true

      destination-port:
        kind: leaf_node
        description: Match destination port
        valueless: true

      vlan:
        kind: node
        anchor: true
        description: VLAN fields included in the lookup key
        children:

          id:
            kind: leaf_node
            valueless: true
            description: Match the outer VLAN identifier

          priority:
            kind: leaf_node
            valueless: true
            description: Match the outer VLAN priority code point
