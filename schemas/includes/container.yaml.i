container:
  kind: node
  description: Podman containers and Netavark networks
  script:
    name: container
    priority: 70
  children:

    registry:
      kind: tag_node
      anchor: true
      description: Ordered image search registries; Docker Hub when none are configured
      hints:
        registry: Registry hostname or IPv4 address, optionally followed by :port; for example docker.io
      validators:
        container-registry: {}
      children:

        priority:
          kind: leaf_node
          description: Search order, lowest first; must be unique
          hints:
            1-65535: Search order, lowest first; must be unique
          validators:
            integer-range: {minimum: 1, maximum: 65535}

    network:
      kind: tag_node
      anchor: true
      description: Named Netavark bridge network
      dependency: container-network
      validators:
        container-network-name: {}
      hints:
        name: Network name (at most 12 characters)
      children:

        description:
          kind: leaf_node
          description: Network description
          hints:
            text: Network description; quote spaces
          validators:
            text: {}

        internal:
          kind: leaf_node
          description: Isolate this network from external networks
          valueless: true

        isolation:
          kind: node
          description: Block direct traffic between separate container bridges by default
          children:

            disable:
              kind: leaf_node
              description: Allow inter-bridge routing when the other network also disables isolation
              valueless: true

        disable-dns:
          kind: leaf_node
          description: Disable container DNS on this network
          valueless: true

        vrf:
          kind: leaf_node
          description: Attach the Netavark bridge to this configured VRF
          hints:
            name: Configured VRF name for the container bridge
          depends: vrf
          validators:
            regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
          suggestors:
            config-path: {path: 'vrf name'}

        mtu:
          kind: leaf_node
          description: Bridge and container interface MTU
          hints:
            68-65535: Bridge and container interface MTU in bytes
          validators:
            integer-range: {minimum: 68, maximum: 65535}

        subnet:
          kind: tag_node
          description: IPv4 or IPv6 network prefix
          hints:
            prefix: IPv4 or IPv6 network prefix without host bits, at least four addresses; for example 10.0.1.0/24 or fd00:1::/64
          validators:
            container-subnet: {}
          children:

            gateway:
              kind: leaf_node
              description: Gateway address inside this subnet
              hints:
                address: IPv4 or IPv6 gateway address inside this subnet
              validators:
                inet-address: {}

    pod:
      kind: tag_node
      anchor: true
      description: Containers sharing networking, hostname and IPC namespaces
      dependency: container-pod
      hints:
        name: Pod name (at most 10 characters; distinct from container names)
      validators:
        regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_-]{0,9}'}
      children:

        include_schema:
        - file: container/network-settings.yaml.i
          as: null

        description:
          kind: leaf_node
          description: Pod description
          hints:
            text: Pod description; quote spaces
          validators:
            text: {}

        disable:
          kind: leaf_node
          description: Stop the pod and all its member containers
          valueless: true

    name:
      kind: tag_node
      anchor: true
      description: Managed container
      validators:
        container-name: {}
      hints:
        name: Container name (at most 10 characters)
      children:

        include_schema:
        - file: container/network-settings.yaml.i
          as: null

        pod:
          kind: leaf_node
          description: Join a configured pod and use its networking and hostname
          hints:
            name: Configured pod name
          depends: container-pod
          validators:
            regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_-]{0,9}'}
          suggestors:
            config-path: {path: 'container pod'}

        description:
          kind: leaf_node
          description: Container description
          hints:
            text: Container description; quote spaces
          validators:
            text: {}

        image:
          kind: leaf_node
          description: Image name with optional registry, tag or digest; add it before commit
          hints:
            image: Image reference; for example alpine, alpine:latest or docker.io/library/alpine:latest
          validators:
            container-image: {}
          suggestors:
            container-images: {}

        capability:
          kind: leaf_node
          description: Add a Linux capability; none drops defaults before adding named capabilities
          choices:
            none: Drop all default capabilities; retain only explicitly named capabilities
          hints:
            capability: Linux capability name; for example net-admin or net-raw
          multi: true
          validators:
            container-capability: {}
          suggestors:
            container-capabilities: {}

        privileged:
          kind: leaf_node
          description: Grant privileged host access, including all capabilities and devices
          valueless: true

        environment-file:
          kind: leaf_node
          description: Environment file relative to /config/containers; explicit environment values override it
          hints:
            path: File relative to /config/containers; for example alpine/environment
          validators:
            container-source: {}

        entrypoint:
          kind: leaf_node
          description: Override image entrypoint; quoted argv, or an empty string to clear
          hints:
            command: Entrypoint and arguments as one quoted string; use "" to clear the image entrypoint
          validators:
            container-entrypoint: {}

        device:
          kind: tag_node
          anchor: true
          description: Host character or block device exposed to the container
          hints:
            /dev/path: Host device path; for example /dev/net/tun
          validators:
            container-device: {}
          children:

            destination:
              kind: leaf_node
              description: Device path inside container; defaults to the source path
              hints:
                /dev/path: Device path inside the container; for example /dev/net/tun
              validators:
                container-device: {}

            permissions:
              kind: leaf_node
              description: Device read, write and mknod permissions
              choices:
                r: Read the device
                w: Write the device
                m: Create device nodes
                rw: Read and write the device
                rm: Read and create device nodes
                wm: Write and create device nodes
                rwm: Read, write and create device nodes
              validators:
                list: {values: 'r w m rw rm wm rwm'}
              default: {mode: direct, value: rwm}

        tmpfs:
          kind: tag_node
          anchor: true
          description: Temporary in-memory filesystem at this container path
          hints:
            /path: Absolute mount directory inside the container; for example /run/cache
          validators:
            container-destination: {}
          children:

            size:
              kind: leaf_node
              description: Maximum bytes, with optional k, m or g binary suffix
              hints:
                size: Positive byte count up to 1 TiB; optional binary k, m or g suffix, for example 64m
              validators:
                container-tmpfs-size: {}

            mode:
              kind: leaf_node
              description: Octal filesystem permissions, for example 1777
              hints:
                octal-mode: Three or four octal digits; for example 755 or 1777
              validators:
                regex: {pattern: '[0-7]{3,4}'}

        disable:
          kind: leaf_node
          description: Stop the container without deleting its configuration or persistent data
          valueless: true

        command:
          kind: leaf_node
          description: Executable passed to the image entrypoint in place of its default command
          hints:
            executable: Executable replacing the image command; for example /bin/sh
          validators:
            text: {}

        argument:
          kind: leaf_node
          description: Quoted argument string, shell-style quoting without shell execution
          hints:
            arguments: Arguments as one quoted string; for example "-c 'sleep infinity'"
          validators:
            container-arguments: {}

        interactive:
          kind: node
          description: Keep container stdin open by default
          children:

            disable:
              kind: leaf_node
              description: Stop keeping container stdin open
              valueless: true

        tty:
          kind: node
          description: Allocate a container terminal by default
          children:

            disable:
              kind: leaf_node
              description: Disable the terminal and preserve separate stdout and stderr
              valueless: true

        environment:
          kind: tag_node
          description: Environment variable
          hints:
            variable: Environment variable name; for example TZ or APP_PORT
          validators:
            regex: {pattern: '[a-zA-Z_][a-zA-Z0-9_]*'}
          children:

            value:
              kind: leaf_node
              description: Environment variable value
              hints:
                text: Environment variable value; quote spaces
              validators:
                text: {}

        restart-policy:
          kind: leaf_node
          description: Systemd container restart policy
          choices:
            'no': Do not automatically restart
            on-failure: Restart after a failed exit
            always: Restart after any exit
          validators:
            list: {values: 'no on-failure always'}
          default: {mode: direct, value: on-failure}

        uid:
          kind: leaf_node
          description: User ID inside the container; auto preserves the image user
          hints:
            auto: Use the user configured by the image
            0-4294967294: Numeric user ID inside the container
          validators:
            mode: OR
            list: {values: auto}
            integer-range: {minimum: 0, maximum: 4294967294}
          default: {mode: direct, value: auto}

        gid:
          kind: leaf_node
          description: Group ID inside the container; auto preserves the selected user's group
          hints:
            auto: Use the selected user's primary group
            0-4294967294: Numeric group ID inside the container
          validators:
            mode: OR
            list: {values: auto}
            integer-range: {minimum: 0, maximum: 4294967294}
          default: {mode: direct, value: auto}

        memory:
          kind: leaf_node
          description: Memory limit in bytes, with optional k, m or g binary suffix
          hints:
            size: Memory from 6 MiB to 1 TiB; optional binary k, m or g suffix, for example 512m
          validators:
            container-memory: {}
          default: {mode: direct, value: 512m}

        cpus:
          kind: leaf_node
          description: CPU allowance, including fractional CPUs
          hints:
            cpus: CPU allowance from 0.01 to 1024, with up to two decimal places; for example 0.5
          validators:
            container-cpus: {}
          default: {mode: direct, value: '1'}

        process-limit:
          kind: leaf_node
          description: Maximum processes and threads in the container
          hints:
            1-65536: Maximum processes and threads in the container
          validators:
            integer-range: {minimum: 1, maximum: 65536}
          default: {mode: direct, value: '256'}

        volume:
          kind: tag_node
          description: Persistent bind mount below /config/containers
          hints:
            name: Name identifying this bind mount, up to 48 characters; for example DATA
          validators:
            regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}'}
          children:

            source:
              kind: leaf_node
              description: Relative directory below /config/containers
              hints:
                path: Directory relative to /config/containers; for example alpine/data
              validators:
                container-source: {}

            destination:
              kind: leaf_node
              description: Absolute directory inside the container
              hints:
                /path: Absolute mount directory inside the container; for example /var/lib/app
              validators:
                container-destination: {}

            read-only:
              kind: leaf_node
              description: Mount without write access
              valueless: true
