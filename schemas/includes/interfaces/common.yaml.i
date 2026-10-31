children: # interface (shared)

  include_schema:
  - file: interfaces/ip-options.yaml.i
    as: null
  - file: interfaces/address.yaml.i
  - file: generic/disable.yaml.i
    replace:
      /description: Administratively disable this interface
  - file: interfaces/mac.yaml.i
  - file: interfaces/mtu.yaml.i
  - file: generic/description.yaml.i
    replace:
      /description: Linux interface alias
      /hints:
        text: Interface description; quote spaces
    add:
      /validators:
        interface-description: {}

  vrf:
    kind: leaf_node
    description: Assign this interface to a configured VRF
    depends: vrf
    validators:
      regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
    suggestors:
      config-path: {path: 'vrf name'}
    hints:
      name: Configured VRF name

  link-group:
    kind: leaf_node
    description: Linux interface group number (0 is the default group)
    validators:
      integer-range: {minimum: 0, maximum: 4294967295}
    hints:
      0-4294967295: Linux link group number
