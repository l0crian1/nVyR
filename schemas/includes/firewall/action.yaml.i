action:
  kind: leaf_node
  description: Rule verdict
  choices:
    jump: Evaluate a named chain in the same address family
    accept: Accept matching traffic
    drop: Silently drop matching traffic
    reject: Reject matching traffic with an error response
    continue: Continue evaluating the next rule
    return: Return to the calling chain
  validators:
    list: {values: accept drop reject jump continue return}
