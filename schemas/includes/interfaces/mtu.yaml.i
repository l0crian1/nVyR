mtu:
  kind: leaf_node
  description: Maximum transmission unit in bytes
  validators:
    mtu: {}
  hints:
    1280-65535: MTU in bytes (subject to device limits)
  default:
    mode: direct
    value: '1500'
