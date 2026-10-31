shellcmd:
  access: dev-admin
  kind: leaf_node
  description: Execute a system command as root (dev-admin only)
  rest: true
  command: ['shellcmd.nvyr.op', 'execute', '@line']
  stream: true
  hints:
    command: Executable followed by its arguments; quote spaces
