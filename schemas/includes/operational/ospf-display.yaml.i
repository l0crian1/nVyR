ospf:
  kind: node
  description: OSPFv2 routing state
  command:
  - "ospf.nvyr.op"
  - "show"
  - "@line"
  children:

    mpls:
      kind: node
      description: MPLS integration
      children:

        ldp-sync:
          kind: node
          description: LDP synchronization state
          command: ['ospf.nvyr.op', 'show', '@line']
          children:

            interface:
              kind: tag_node
              description: Select an interface
              validators:
                regex: {pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,14}'}
              choices:
                all: All interfaces
              suggestors:
                interfaces: {}
              command: ['ospf.nvyr.op', 'show', '@line']
              children:

                json:
                  kind: node
                  description: Native JSON output
                  command: ['ospf.nvyr.op', 'show', '@line']
                  children: {}

            json:
              kind: node
              description: Native JSON output
              command: ['ospf.nvyr.op', 'show', '@line']
              children: {}

    include_schema:
    - file: operational/ospf-context.yaml.i
      as: null

    vrf:
      kind: tag_node
      description: OSPF state in a VRF
      validators:
        regex:
          pattern: '[A-Za-z][A-Za-z0-9_.-]{0,14}'
      hints:
        vrf: OSPF state in a VRF
      children:

        include_schema:
        - file: operational/ospf-context.yaml.i
          as: null
      command:
      - "ospf.nvyr.op"
      - "show"
      - "@line"
      choices:
        default: Default routing instance
        all: All routing instances
      suggestors:
        config-path:
          path: vrf name

    vrfs:
      kind: node
      description: OSPF routing instance summary
      command:
      - "ospf.nvyr.op"
      - "show"
      - "@line"
