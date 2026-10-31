protocol:
  kind: leaf_node
  description: IP protocol
  multi: true
  validators:
    ip-protocol: {}
  choices:
    ip: IP protocol 0 (IPv6 Hop-by-Hop Options)
    icmp: Internet Control Message Protocol
    igmp: Internet Group Management Protocol
    ggp: Gateway-to-Gateway Protocol
    ipencap: IPv4 encapsulation (IP protocol 4)
    st: Internet Stream Protocol
    tcp: Transmission Control Protocol
    egp: Exterior Gateway Protocol
    igp: Private interior gateway protocol (including Cisco IGRP)
    pup: PARC Universal Packet protocol
    udp: User Datagram Protocol
    hmp: Host Monitoring Protocol
    xns-idp: Xerox Network Systems Internet Datagram Protocol
    rdp: Reliable Data Protocol
    iso-tp4: ISO Transport Protocol Class 4
    dccp: Datagram Congestion Control Protocol
    xtp: Xpress Transport Protocol
    ddp: AppleTalk Datagram Delivery Protocol
    idpr-cmtp: Inter-Domain Policy Routing Control Message Transport Protocol
    ipv6: IPv6 encapsulation
    ipv6-route: IPv6 routing header
    ipv6-frag: IPv6 fragment header
    idrp: Inter-Domain Routing Protocol
    rsvp: Resource Reservation Protocol
    gre: Generic Routing Encapsulation
    esp: IPsec Encapsulating Security Payload
    ah: IPsec Authentication Header
    skip: Simple Key-Management for Internet Protocols
    ipv6-icmp: Internet Control Message Protocol for IPv6
    ipv6-nonxt: IPv6 no-next-header indicator
    ipv6-opts: IPv6 destination options header
    rspf: Radio Shortest Path First
    vmtp: Versatile Message Transaction Protocol
    eigrp: Enhanced Interior Gateway Routing Protocol
    ospf: Open Shortest Path First
    ax.25: AX.25 amateur packet-radio frames
    ipip: IP-within-IP Encapsulation Protocol (IP protocol 94)
    etherip: Ethernet-within-IP encapsulation
    encap: Encapsulation Header
    pim: Protocol Independent Multicast
    ipcomp: IP Payload Compression Protocol
    vrrp: Virtual Router Redundancy Protocol
    l2tp: Layer Two Tunneling Protocol
    isis: Intermediate System to Intermediate System over IPv4
    sctp: Stream Control Transmission Protocol
    fc: Fibre Channel
    mobility-header: IPv6 mobility header
    udplite: Lightweight User Datagram Protocol
    mpls-in-ip: Multiprotocol Label Switching encapsulated in IP
    manet: Mobile Ad Hoc Network protocols
    hip: Host Identity Protocol
    shim6: IPv6 multihoming shim protocol
    wesp: Wrapped Encapsulating Security Payload
    rohc: Robust Header Compression
    ethernet: Ethernet encapsulation in IP
