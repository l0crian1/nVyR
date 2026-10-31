vrf:
  kind: leaf_node
  description: Routing instance for probes and hostname resolution
  validators:
    regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
  choices:
    default: Default routing instance
  suggestors:
    config-path: {path: 'vrf name'}
  hints:
    name: VRF name
