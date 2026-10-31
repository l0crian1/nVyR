children: # forwarding path (shared)

  include_schema:
  - file: protocols/static/path-options.yaml.i
    as: null

  vrf:
    kind: leaf_node
    description: VRF used to resolve this next hop (defaults to the route VRF)
    depends: vrf
    validators:
      regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
    hints:
      name: Next-hop VRF name, or default
    choices:
      default: Resolve the next hop in the default VRF

  weight:
    kind: leaf_node
    description: Relative traffic weight of this multipath next hop
    validators:
      integer-range: {minimum: 1, maximum: 65535}
    hints:
      1-65535: Multipath weight
