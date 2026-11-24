macsec:
  kind: node
  access: net-admin
  description: Generate MACsec key material
  children:

    preshared-key:
      kind: node
      description: Generate a CAK and CKN for both ends of a link
      command: ['macsec.nvyr.op','generate']
      children:

        bits:
          kind: tag_node
          description: Length of the CAK
          choices:
            '128': 128-bit CAK (default)
            '256': 256-bit CAK
          validators:
            list: {values: '128 256'}
          command: ['macsec.nvyr.op','generate','--bits','@5']
