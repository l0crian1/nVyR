children: # shared Zebra routing-table displays

  include_schema:
  - file: operational/route-destination.yaml.i
  - file: operational/route-selectors.yaml.i
    as: null

  static:
    kind: node
    description: Static routes in Zebra's routing table
    command: ['static.nvyr.op', 'show', '@line']
    children: # static

      failed:
        kind: node
        description: Static routes that failed kernel installation
        command: ['static.nvyr.op', 'show', '@line']

  failed:
    kind: node
    description: Routes that failed kernel installation
    command: ['static.nvyr.op', 'show', '@line']

  summary:
    kind: node
    description: Route and installed-path counts by protocol
    command: ['static.nvyr.op', 'show', '@line']
    children: # summary

      prefix:
        kind: node
        description: Count prefixes instead of paths
        command: ['static.nvyr.op', 'show', '@line']

      table:
        kind: tag_node
        description: Summarize a routing table
        command: ['static.nvyr.op', 'show', '@line']
        validators:
          integer-range: {minimum: 1, maximum: 4294967295}
        hints:
          number: Routing table ID
        children: # table

          prefix:
            kind: node
            description: Count prefixes instead of paths
            command: ['static.nvyr.op', 'show', '@line']
