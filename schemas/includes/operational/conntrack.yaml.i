conntrack:
  kind: node
  anchor: true
  description: Tracked connections and NAT state
  command: ['conntrack.nvyr.op', 'show', '@line']
  children:
    include_schema:
    - file: operational/conntrack-filters.yaml.i
      as: null

    statistics:
      kind: leaf_node
      valueless: true
      description: Connection table occupancy and aggregate kernel diagnostics
