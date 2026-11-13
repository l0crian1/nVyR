ipv4-labeled-unicast:
  kind: node
  description: IPv4 labeled-unicast path selection
  anchor: true
  children:

    maximum-paths:
      kind: node
      description: Maximum equal-cost paths
      anchor: true
      children:

        ebgp:
          kind: leaf_node
          description: External equal-cost paths
          validators:
            integer-range:
              minimum: 1
              maximum: 256
          hints:
            1-256: External equal-cost paths

        ibgp:
          kind: leaf_node
          description: Internal equal-cost paths
          validators:
            integer-range:
              minimum: 1
              maximum: 256
          hints:
            1-256: Internal equal-cost paths
