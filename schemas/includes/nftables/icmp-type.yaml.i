icmp-type:
  kind: leaf_node
  multi: true
  description: Match IPv4 ICMP type by name
  validators:
    icmp-type: {}
  choices:
    echo-reply: Echo reply (type 0)
    destination-unreachable: Destination unreachable (type 3)
    source-quench: Source quench (type 4)
    redirect: Redirect (type 5)
    echo-request: Echo request (type 8)
    router-advertisement: Router advertisement (type 9)
    router-solicitation: Router solicitation (type 10)
    time-exceeded: Time exceeded (type 11)
    parameter-problem: Parameter problem (type 12)
    timestamp-request: Timestamp request (type 13)
    timestamp-reply: Timestamp reply (type 14)
    info-request: Info request (type 15)
    info-reply: Info reply (type 16)
    address-mask-request: Address mask request (type 17)
    address-mask-reply: Address mask reply (type 18)
