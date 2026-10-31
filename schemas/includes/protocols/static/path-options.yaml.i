children: # static path (shared)

  include_schema:
  - file: generic/description.yaml.i
    replace:
      /description: Static path description
      /hints:
        text: Description; quote spaces
    add:
      /validators:
        text: {}
  - file: generic/disable.yaml.i
    replace:
      /description: Disable this static path

  distance:
    kind: leaf_node
    description: Administrative distance (lower values preferred)
    validators:
      integer-range: {minimum: 1, maximum: 255}
    hints:
      1-255: Administrative distance
    default:
      mode: direct
      value: '1'

  metric:
    kind: leaf_node
    description: Route metric (lower values preferred at the same distance)
    validators:
      integer-range: {minimum: 0, maximum: 4294967295}
    hints:
      0-4294967295: Route metric
    default:
      mode: direct
      value: '0'

  tag:
    kind: leaf_node
    description: Route tag for routing policy
    validators:
      integer-range: {minimum: 1, maximum: 4294967295}
    hints:
      1-4294967295: Route tag
