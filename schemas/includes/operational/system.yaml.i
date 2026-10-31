system:
  kind: node
  description: System information
  children: # system

    config:
      kind: node
      description: Configuration system information
      children:

        script-priority:
          kind: node
          description: Configuration script priorities and declaring paths
          command: ['system.nvyr.op', 'script_priority']

    packages:
      kind: tag_node
      optional_value: true
      description: Debian packages, versions, architectures and descriptions
      command: ['system.nvyr.op', 'packages', '--name', '@4']
      validators:
        regex: {pattern: '[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?'}
      hints:
        package: Exact package name, including architecture qualifier when present
      suggestors:
        installed-packages: {}

    name-server:
      kind: node
      description: Published system DNS servers and their static or DHCP sources
      command: ['resolver.nvyr.op', 'servers']

    services:
      kind: node
      description: Managed service health and configured instances
      command: ['services.nvyr.op', 'show']
      children:

        configd:
          kind: node
          description: Configuration daemon
          command: ['services.nvyr.op', 'show', '--service', 'configd']
          children:

            detail:
              kind: node
              description: Detailed process and readiness information
              command: ['services.nvyr.op', 'show', '--service', 'configd', '--detail']

        netlinkd:
          kind: node
          description: Interface manager
          command: ['services.nvyr.op', 'show', '--service', 'netlinkd']
          children:

            detail:
              kind: node
              description: Detailed process and readiness information
              command: ['services.nvyr.op', 'show', '--service', 'netlinkd', '--detail']

        frr:
          kind: node
          description: Routing daemons
          command: ['services.nvyr.op', 'show', '--service', 'frr']
          children:

            detail:
              kind: node
              description: Detailed process and readiness information
              command: ['services.nvyr.op', 'show', '--service', 'frr', '--detail']

        ssh:
          kind: node
          description: SSH service
          command: ['services.nvyr.op', 'show', '--service', 'ssh']
          children:

            detail:
              kind: node
              description: Detailed process and readiness information
              command: ['services.nvyr.op', 'show', '--service', 'ssh', '--detail']

            vrf:
              kind: tag_node
              description: Service health in a routing instance
              command: ['services.nvyr.op', 'show', '--service', 'ssh', '--vrf', '@6']
              validators:
                regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
              choices:
                default: Default routing instance
              suggestors:
                config-path: {path: 'vrf name'}
              hints:
                name: Routing instance name

        ntp:
          kind: node
          description: Clock synchronization
          command: ['services.nvyr.op', 'show', '--service', 'ntp']
          children:

            detail:
              kind: node
              description: Detailed process and readiness information
              command: ['services.nvyr.op', 'show', '--service', 'ntp', '--detail']

            vrf:
              kind: tag_node
              description: Service health in a routing instance
              command: ['services.nvyr.op', 'show', '--service', 'ntp', '--vrf', '@6']
              validators:
                regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
              choices:
                default: Default routing instance
              suggestors:
                config-path: {path: 'vrf name'}
              hints:
                name: Routing instance name

        dhcp-server:
          kind: node
          description: DHCPv4 servers
          command: ['services.nvyr.op', 'show', '--service', 'dhcp-server']
          children:

            detail:
              kind: node
              description: Detailed process and readiness information
              command: ['services.nvyr.op', 'show', '--service', 'dhcp-server', '--detail']

            vrf:
              kind: tag_node
              description: Service health in a routing instance
              command: ['services.nvyr.op', 'show', '--service', 'dhcp-server', '--vrf', '@6']
              validators:
                regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
              choices:
                default: Default routing instance
              suggestors:
                config-path: {path: 'vrf name'}
              hints:
                name: Routing instance name

        dhcpv6-server:
          kind: node
          description: DHCPv6 servers
          command: ['services.nvyr.op', 'show', '--service', 'dhcpv6-server']
          children:

            detail:
              kind: node
              description: Detailed process and readiness information
              command: ['services.nvyr.op', 'show', '--service', 'dhcpv6-server', '--detail']

            vrf:
              kind: tag_node
              description: Service health in a routing instance
              command: ['services.nvyr.op', 'show', '--service', 'dhcpv6-server', '--vrf', '@6']
              validators:
                regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
              choices:
                default: Default routing instance
              suggestors:
                config-path: {path: 'vrf name'}
              hints:
                name: Routing instance name

        container:
          kind: node
          description: Managed containers and pods
          command: ['services.nvyr.op', 'show', '--service', 'container']
          children:

            detail:
              kind: node
              description: Detailed process and readiness information
              command: ['services.nvyr.op', 'show', '--service', 'container', '--detail']

            vrf:
              kind: tag_node
              description: Service health in a routing instance
              command: ['services.nvyr.op', 'show', '--service', 'container', '--vrf', '@6']
              validators:
                regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
              choices:
                default: Default routing instance
              suggestors:
                config-path: {path: 'vrf name'}
              hints:
                name: Routing instance name

            name:
              kind: tag_node
              description: Detailed health of one configured container or pod
              command: ['services.nvyr.op', 'show', '--service', 'container', '--name', '@6']
              validators:
                regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}'}
              suggestors:
                container-instances: {}
              hints:
                name: Container or pod name

    uptime:
      kind: node
      description: System uptime and load averages
      command: ['uptime']

    cpu:
      kind: node
      description: Processor model and topology summary
      command: ['system.nvyr.op', 'cpu']
      children:

        usage:
          kind: node
          description: Total and per-CPU usage sampled over one second
          command: ['system.nvyr.op', 'cpu_usage']

    memory:
      kind: node
      description: Memory and swap usage in human-readable units
      command: ['free', '-h']

    storage:
      kind: node
      description: Filesystem space and inode usage
      command: ['system.nvyr.op', 'storage']

    processes:
      kind: node
      description: Processes by PID, with lifetime average CPU and resident memory usage
      command: ['system.nvyr.op', 'processes']
      children:

        cpu:
          kind: node
          description: Sort processes by lifetime average CPU usage
          command: ['system.nvyr.op', 'processes', '--sort', 'cpu']

        memory:
          kind: node
          description: Sort processes by resident memory usage
          command: ['system.nvyr.op', 'processes', '--sort', 'memory']

    image:
      kind: node
      description: Installed images, running image and default boot image
      command: ['images.nvyr.op', 'show']
