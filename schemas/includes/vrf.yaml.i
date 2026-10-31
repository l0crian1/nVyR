vrf:
  kind: node
  description: Virtual routing and forwarding instances
  script:
    name: vrf_conntrack
    priority: 4
    watch-before:
    - vrf name * table
    - interfaces
    - container network
  children: # vrf

    name:
      kind: tag_node
      rename: false
      description: VRF instance
      dependency: vrf
      validators:
        regex: {pattern: '(?!default$)[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
      hints:
        name: VRF device name (1-15 characters; default is reserved)
      script:
        name: vrf
        priority: 5
      children: # name

        service:
          kind: node
          description: Services in this VRF
          children:

            include_schema:
            - file: service/dhcp-server.yaml.i
              remove:
              - /children/update-hostfile
              replace:
                /script/register/vrf: {tag: name}
            - file: service/dhcpv6-server.yaml.i
              replace:
                /script/register/vrf: {tag: name}

        protocols:
          kind: node
          description: Routing protocols in this VRF
          children: # protocols

            include_schema:
            - file: protocols/static.yaml.i
              replace:
                /script/register/vrf: {tag: name}
            - file: protocols/bgp.yaml.i
              replace:
                /script/register/vrf: {tag: name}

        table:
          kind: leaf_node
          description: Unique routing table ID for this VRF
          validators:
            integer-ranges: {ranges: [[100, 251], [256, 4294967295]]}
          hints:
            100-251: Routing table ID
            256-4294967295: Routing table ID
