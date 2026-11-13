ipv6-labeled-unicast:
  kind: node
  description: IPv6 labeled-unicast path selection
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

    next-hop:
      kind: node
      description: IPv6 next-hop selection
      children:

        prefer-global:
          kind: leaf_node
          description: Prefer the global next hop over the link-local next hop
          valueless: true
