connection-status:
  kind: leaf_node
  multi: true
  joinable: true
  description: Match an exact connection tracking status combination
  validators:
    list:
      values: expected seen-reply assured confirmed snat dnat seq-adjust snat-done dnat-done dying fixed-timeout helper offload
      separator: ','
  hints:
    flag: Exact status flag; use and to combine, repeat the setting for alternatives
  choices:
    expected: Connection expected by a connection-tracking helper
    seen-reply: Reply traffic has been seen
    assured: Connection assured against early eviction
    confirmed: Initial packet has completed connection tracking
    snat: Connection uses source NAT
    dnat: Connection uses destination NAT
    seq-adjust: TCP sequence adjustment is required
    snat-done: Source NAT lookup is complete
    dnat-done: Destination NAT lookup is complete
    dying: Connection is being deleted
    fixed-timeout: Connection timeout is fixed
    helper: Connection is monitored by a helper
    offload: Connection is offloaded to a flowtable
