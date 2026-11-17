wireguard:
  kind: node
  access: net-admin
  description: Generate WireGuard keys without changing configuration
  children:

    key-pair:
      kind: node
      description: Generate a private and public key pair
      command: ['wireguard.nvyr.op', 'generate', 'key-pair']

    preshared-key:
      kind: node
      description: Generate an additional symmetric key
      command: ['wireguard.nvyr.op', 'generate', 'preshared-key']
