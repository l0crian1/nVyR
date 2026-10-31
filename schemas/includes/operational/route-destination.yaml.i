destination:
  kind: tag_node
  positional: true
  description: Look up a destination address or prefix
  command: ['static.nvyr.op', 'show', '@line']
  validators:
    mode: OR
    ipv4-address: {}
    ipv4-prefix: {}
  hints:
    x.x.x.x: IPv4 destination address
    x.x.x.x/x: IPv4 destination prefix
  children: # destination

    longer-prefixes:
      kind: node
      description: Routes contained within the specified prefix
      command: ['static.nvyr.op', 'show', '@line']
      children: # longer-prefixes

        static:
          kind: node
          description: Static routes contained within this prefix
          command: ['static.nvyr.op', 'show', '@line']
