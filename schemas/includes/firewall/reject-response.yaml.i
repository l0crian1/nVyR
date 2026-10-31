reject-response:
  kind: leaf_node
  description: Default response for firewall reject actions
  choices:
    port-unreachable: Destination port is unreachable
    admin-prohibited: Communication is administratively prohibited
    no-route: No route to the destination
    host-unreachable: Destination host is unreachable
  validators:
    list: {values: port-unreachable admin-prohibited no-route host-unreachable}
