children: # firewall chain defaults

  default-action:
    kind: leaf_node
    description: Default verdict
    choices:
      accept: Accept matching traffic
      drop: Silently drop matching traffic
      reject: Reject matching traffic with the global error response
    validators:
      list: {values: accept drop reject}
    default:
      mode: direct
      value: accept

  default-log:
    kind: leaf_node
    description: Log packets reaching the default action
    valueless: true
