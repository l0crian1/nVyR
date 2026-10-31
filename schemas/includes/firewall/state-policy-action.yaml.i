action:
  kind: leaf_node
  description: Rule verdict
  choices:
    accept: Accept matching traffic
    drop: Silently drop matching traffic
    reject: Reject matching traffic with the global error response
  validators:
    list: {values: accept drop reject}
