children: # map result

  action:
    kind: leaf_node
    description: Verdict returned by this entry
    validators:
      list: {values: accept drop continue return jump}
    choices:
      accept: Accept matching traffic
      drop: Drop matching traffic
      continue: Continue evaluating rules
      return: Return to the calling chain
      jump: Evaluate a named chain in the same address family

  port:
    kind: leaf_node
    description: Result transport port
    validators:
      port: {}
    hints:
      1-65535: Result port
