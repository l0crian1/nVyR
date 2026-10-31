per:
  kind: leaf_node
  joinable: true
  description: Separate allowance for each unique combination of packet fields
  validators:
    list:
      values: source-address destination-address source-port destination-port protocol inbound-interface outbound-interface inbound-link-group outbound-link-group source-mac destination-mac packet-mark connection-mark
      separator: ','
  choices:
    source-address: Source IPv4 or IPv6 address
    destination-address: Destination IPv4 or IPv6 address
    source-port: Source port (TCP, UDP, UDP-Lite, SCTP or DCCP)
    destination-port: Destination port (TCP, UDP, UDP-Lite, SCTP or DCCP)
    protocol: Transport protocol
    inbound-interface: Incoming interface name
    outbound-interface: Outgoing interface name
    inbound-link-group: Incoming Linux interface link group
    outbound-link-group: Outgoing Linux interface link group
    source-mac: Source Ethernet address
    destination-mac: Destination Ethernet address
    packet-mark: Packet mark
    connection-mark: Connection tracking mark
