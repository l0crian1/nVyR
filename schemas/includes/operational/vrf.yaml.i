vrf:
  kind: tag_node
  optional_value: true
  description: VRF devices and their member interfaces
  command: ['vrf.nvyr.op', 'show', '--name', '@3']
  validators:
    regex: {pattern: '(?!default$)[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
  hints:
    name: VRF device name
  suggestors:
    config-path: {path: 'vrf name'}
