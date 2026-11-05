neighbor:
  kind: tag_node
  anchor: true
  description: Permanent IPv6 neighbor entry
  strip_kind: ipv6
  validators:
    ipv6-address: {}
  hints:
    h:h::h: Neighbor IPv6 address without a prefix
  children:

    mac-address:
      kind: leaf_node
      description: Permanent destination Ethernet address
      strip_kind: mac
      validators:
        mac: {}
      hints:
        xx:xx:xx:xx:xx:xx: Nonzero unicast Ethernet MAC address

    include_schema:
    - file: generic/description.yaml.i
      replace:
        /description: Description of this static neighbor
