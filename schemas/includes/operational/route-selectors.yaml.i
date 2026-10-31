children: # Native FRR route selectors

  bgp:
    kind: node
    description: Routes learned through BGP
    command: ['static.nvyr.op', 'show', '@line']

  connected:
    kind: node
    description: Directly connected networks
    command: ['static.nvyr.op', 'show', '@line']

  kernel:
    kind: node
    description: Routes learned from the kernel
    command: ['static.nvyr.op', 'show', '@line']

  local:
    kind: node
    description: Routes to addresses owned by this router
    command: ['static.nvyr.op', 'show', '@line']

  tag:
    kind: leaf_node
    description: Routes with a specific route tag
    hints:
      1-4294967295: Route tag
    validators:
      integer-range: {minimum: 1, maximum: 4294967295}
    command: ['static.nvyr.op', 'show', '@line']
