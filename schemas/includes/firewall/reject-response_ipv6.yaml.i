reject-response:
  kind: leaf_node
  description: Response sent by action reject; overrides the global default
  choices:
    port-unreachable: Destination port is unreachable
    admin-prohibited: Communication is administratively prohibited
    no-route: No route to the destination
    host-unreachable: Destination host is unreachable
    tcp-reset: Reset the TCP connection; requires protocol tcp
    addr-unreachable: Destination address is unreachable
    policy-fail: Source address failed ingress or egress policy
    reject-route: Route to the destination is rejected
  validators:
    list: {values: port-unreachable admin-prohibited no-route host-unreachable tcp-reset addr-unreachable policy-fail reject-route}
