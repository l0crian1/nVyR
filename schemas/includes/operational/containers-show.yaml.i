containers:
  kind: node
  description: Containers, including stopped workloads and failed services
  command: ['containers.nvyr.op', 'show']
  children:

    pods:
      kind: node
      description: Pods, shared networks and member container states
      command: ['containers.nvyr.op', 'pods']

    pod:
      kind: leaf_node
      description: Pod details, addresses, published ports and members
      hints:
        name: Configured pod name
      suggestors:
        config-path: {path: 'container pod'}
      command: ['containers.nvyr.op', 'pods', '--name', '@4']

    name:
      kind: tag_node
      description: Display one container
      hints:
        name: Configured container name
      suggestors:
        config-path: {path: 'container name'}
      command: ['containers.nvyr.op', 'show', '--name', '@4']
      children:

        detail:
          kind: node
          description: Container state, networks, mounts and resource limits
          command: ['containers.nvyr.op', 'show', '--name', '@4', '--detail']

    statistics:
      kind: node
      description: Current CPU, memory, network and storage usage
      command: ['containers.nvyr.op', 'statistics']
      children:

        name:
          kind: tag_node
          description: Resource usage for one running container
          hints:
            name: Configured container name
          suggestors:
            config-path: {path: 'container name'}
          command: ['containers.nvyr.op', 'statistics', '--name', '@5']
          children:

            follow:
              kind: node
              description: Refresh resource usage until interrupted
              command: ['containers.nvyr.op', 'statistics', '--name', '@5', '--follow']
              stream: true

    networks:
      kind: node
      description: Container networks, addresses, VRFs and attachments
      command: ['containers.nvyr.op', 'networks']
      children:

        name:
          kind: leaf_node
          description: Display one container network and its attachments
          hints:
            name: Configured container network name
          suggestors:
            config-path: {path: 'container network'}
          command: ['containers.nvyr.op', 'networks', '--name', '@5']

    images:
      kind: node
      description: Installed images and the containers using them
      command: ['containers.nvyr.op', 'images']
