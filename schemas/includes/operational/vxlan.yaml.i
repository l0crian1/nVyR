vxlan:
  kind: tag_node
  optional_value: true
  description: VXLAN interfaces and effective tunnel settings
  command: ['vxlan.nvyr.op', 'show', '--interface', '@4']
  validators:
    regex: {pattern: 'vxlan[0-9]+'}
  suggestors:
    interfaces: {prefix: vxlan}
  hints:
    vxlanN: VXLAN interface name
  children:

    fdb:
      kind: leaf_node
      valueless: true
      description: Tunnel forwarding database and remote VTEPs
      command: ['vxlan.nvyr.op', 'show', '--interface', '@4', '--section', 'fdb']

    vni:
      kind: leaf_node
      valueless: true
      description: VLAN to VNI mappings and receive filter
      command: ['vxlan.nvyr.op', 'show', '--interface', '@4', '--section', 'vni']
