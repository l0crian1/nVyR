children: # interface display (shared)

  detail:
    kind: leaf_node
    description: Detailed interface information
    valueless: true

  statistics:
    kind: leaf_node
    description: Interface statistics
    valueless: true

  offload:
    kind: leaf_node
    description: Ethernet offload feature status
    valueless: true

  queues:
    kind: leaf_node
    description: Ethernet channels and ring sizes
    valueless: true

  hardware-statistics:
    kind: leaf_node
    description: Driver-provided hardware counters
    valueless: true

  transceiver:
    kind: leaf_node
    description: Transceiver identity and optical diagnostics
    valueless: true
