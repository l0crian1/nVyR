children:

  interface:
    kind: leaf_node
    description: Show neighbors on one interface
    validators:
      regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.:-]{0,14}'}
    suggestors:
      interfaces: {}
    hints:
      interface: Interface name

  vrf:
    kind: leaf_node
    description: Show neighbors in one routing instance
    validators:
      regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
    choices:
      default: Default routing instance
    suggestors:
      config-path: {path: 'vrf name'}
    hints:
      name: VRF name
