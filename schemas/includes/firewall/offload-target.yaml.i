offload-target:
  kind: leaf_node
  depends: firewall-flowtable
  description: Configured flowtable used by action offload
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Existing firewall flowtable name
  suggestors:
    config-path: {path: 'firewall flowtable'}
