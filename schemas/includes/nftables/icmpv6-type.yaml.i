icmp-type:
  kind: leaf_node
  multi: true
  description: Match IPv6 ICMP type by name
  validators:
    icmpv6-type: {}
  choices:
    destination-unreachable: Destination unreachable (type 1)
    packet-too-big: Packet too big (type 2)
    time-exceeded: Time exceeded (type 3)
    parameter-problem: Parameter problem (type 4)
    echo-request: Echo request (type 128)
    echo-reply: Echo reply (type 129)
    mld-listener-query: MLD listener query (type 130)
    mld-listener-report: MLD listener report (type 131)
    mld-listener-done: MLD listener done (type 132)
    mld-listener-reduction: MLD listener reduction (type 132)
    nd-router-solicit: ND router solicit (type 133)
    nd-router-advert: ND router advert (type 134)
    nd-neighbor-solicit: ND neighbor solicit (type 135)
    nd-neighbor-advert: ND neighbor advert (type 136)
    nd-redirect: ND redirect (type 137)
    router-renumbering: Router renumbering (type 138)
    ind-neighbor-solicit: Inverse ND neighbor solicit (type 141)
    ind-neighbor-advert: Inverse ND neighbor advert (type 142)
    mld2-listener-report: MLDv2 listener report (type 143)
