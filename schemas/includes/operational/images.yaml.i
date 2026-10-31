children: # image management commands

  install:
    access: net-admin
    kind: node
    description: Install nVyR (net-admin or higher)
    children: # install

      image:
        kind: node
        description: Guided installation from the live ISO
        command: ['images.nvyr.op', 'install']
        stream: true

  add:
    access: net-admin
    kind: node
    description: Add system resources (net-admin or higher)
    children: # add

      container:
        kind: node
        description: Container resources
        children:

          image:
            kind: leaf_node
            description: Pull an image using its optional registry, tag or digest
            hints:
              image: Image reference; for example alpine, alpine:latest or docker.io/library/alpine:latest
            validators:
              container-image: {}
            suggestors:
              container-images: {}
            command: ['containers.nvyr.op', 'add', '@4']
            stream: true

      system:
        kind: node
        description: System resources
        children: # system

          image:
            kind: leaf_node
            description: Install an additional nVyR image
            command: ['images.nvyr.op', 'add', '@4']
            stream: true
            hints:
              ISO-or-URL: ISO filename in /config/nvyr-images, local path, or HTTP(S) URL
            suggestors:
              image-files: {}

  rename:
    access: net-admin
    kind: node
    description: Rename an installed image (net-admin or higher)
    children: # rename

      system:
        kind: node
        description: System resources
        children: # system

          image:
            kind: tag_node
            description: Rename an image without moving its persistent files
            hints:
              name: Installed nVyR image name
            suggestors:
              installed-images: {}
            children: # image

              to:
                kind: leaf_node
                description: New image name
                command: ['images.nvyr.op', 'rename', '@4', '@6']
                stream: true
                hints:
                  name: New image name

  delete:
    access: net-admin
    kind: node
    description: Remove an installed image (net-admin or higher)
    children: # delete

      system:
        kind: node
        description: System resources
        children: # system

          image:
            kind: leaf_node
            description: Delete an inactive, non-default image and its persistent files
            hints:
              name: Installed nVyR image name
            command: ['images.nvyr.op', 'delete', '@4']
            stream: true
            suggestors:
              installed-images: {}
