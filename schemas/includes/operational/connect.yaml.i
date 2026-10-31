connect:
  kind: node
  access: net-admin
  description: Open a session to a managed resource
  children:

    container:
      kind: tag_node
      description: Open a shell in a running container
      hints:
        name: Configured container name
      validators:
        regex: {pattern: '[A-Za-z][A-Za-z0-9_-]{0,9}'}
      suggestors:
        config-path: {path: 'container name'}
      command: ['containers.nvyr.op', 'connect', '@3']
      stream: true
      children:

        send-command:
          kind: leaf_node
          description: Run a shell command inside the container
          hints:
            command: Quoted command executed by /bin/sh inside the container
          command: ['containers.nvyr.op', 'connect', '@3', '--send-command', '@5']
          stream: true
