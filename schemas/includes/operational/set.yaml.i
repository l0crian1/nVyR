set:
  kind: node
  description: Adjust operational settings
  children: # set

    terminal:
      kind: node
      description: Terminal settings for this CLI session
      children: # terminal

        length:
          kind: leaf_node
          description: Output lines per page; 0 disables automatic paging
          command: ['terminal-length']
          validators:
            nonnegative-integer: {}
          hints:
            lines: Output lines per page; 0 disables automatic paging

    system:
      access: net-admin
      kind: node
      description: System boot settings
      children: # system

        boot:
          kind: node
          description: GRUB boot selection
          children: # boot

            image:
              kind: leaf_node
              description: Default boot image
              hints:
                name: Installed nVyR image name
              command: ['images.nvyr.op', 'select', '@5']
              stream: true
              suggestors:
                installed-images: {}
