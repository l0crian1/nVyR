restart:
  kind: node
  access: net-admin
  description: Restart a managed service
  children:

    container:
      kind: tag_node
      optional_value: true
      description: Restart an enabled container through its managed service
      hints:
        name: Configured container name
      suggestors:
        config-path: {path: 'container name'}
      command: ['containers.nvyr.op', 'restart', '@3']
      stream: true
      children:

        pod:
          kind: leaf_node
          description: Restart a pod and its enabled member containers
          hints:
            name: Configured pod name
          suggestors:
            config-path: {path: 'container pod'}
          command: ['containers.nvyr.op', 'restart_pod', '@4']
          stream: true
