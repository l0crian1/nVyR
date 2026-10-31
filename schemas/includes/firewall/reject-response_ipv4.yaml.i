reject-response:
  kind: leaf_node
  description: Response sent by action reject; overrides the global default
  choices:
    port-unreachable: Destination port is unreachable
    admin-prohibited: Communication is administratively prohibited
    no-route: No route to the destination
    host-unreachable: Destination host is unreachable
    tcp-reset: Reset the TCP connection; requires protocol tcp
    net-unreachable: Destination network is unreachable
    prot-unreachable: Destination protocol is unreachable
    frag-needed: Fragmentation is required
    net-prohibited: Destination network is administratively prohibited
    host-prohibited: Destination host is administratively prohibited
  validators:
    list: {values: port-unreachable admin-prohibited no-route host-unreachable tcp-reset net-unreachable prot-unreachable frag-needed net-prohibited host-prohibited}
