update:
  kind: node
  access: net-admin
  description: Update resources
  children:

    firewall:
      kind: node
      description: Firewall data sources
      children:

        geoip:
          kind: node
          description: Check DB-IP for changed country data and refresh address-groups
          command: ['geoip.nvyr.op', 'update']
          stream: true

        domain-group:
          kind: node
          description: DNS-backed firewall group lookups
          command: ['domain_groups.nvyr.op', 'update']
          stream: true
          children:

            ipv4:
              kind: tag_node
              optional_value: true
              description: IPv4 domain groups, optionally filtered by name
              command: ['domain_groups.nvyr.op', 'update', '--family', 'ipv4', '--name', '@5']
              stream: true
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              suggestors:
                config-path: {path: 'firewall group domain-group ipv4'}
              hints:
                name: Domain group name

            ipv6:
              kind: tag_node
              optional_value: true
              description: IPv6 domain groups, optionally filtered by name
              command: ['domain_groups.nvyr.op', 'update', '--family', 'ipv6', '--name', '@5']
              stream: true
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
              suggestors:
                config-path: {path: 'firewall group domain-group ipv6'}
              hints:
                name: Domain group name

    container:
      kind: node
      description: Container resources
      children:

        image:
          kind: node
          description: Download an updated image without restarting containers
          children:

            name:
              kind: leaf_node
              description: Image name with optional registry, tag or digest
              hints:
                image: Image reference; for example alpine, alpine:latest or docker.io/library/alpine:latest
              validators:
                container-image: {}
              suggestors:
                container-images: {}
              command: ['containers.nvyr.op', 'update', '@5']
              stream: true

            container:
              kind: leaf_node
              description: Update the image referenced by a configured container
              hints:
                name: Configured container name
              suggestors:
                config-path: {path: 'container name'}
              command: ['containers.nvyr.op', 'update_container', '@5']
              stream: true
