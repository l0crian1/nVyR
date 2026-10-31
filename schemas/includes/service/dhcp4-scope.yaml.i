children:

  description:
    kind: leaf_node
    description: Administrative description
    hints:
      text: Administrative description; quote spaces; at most 255 characters
    validators:
      length:
        maximum: 255

  disable:
    kind: leaf_node
    description: Disable this configuration without removing it
    valueless: true

  lease-time:
    kind: leaf_node
    description: Time a DHCPv4 lease remains valid; use s, m, h or d
    validators:
      duration:
        maximum: 4294967294
    hints:
      duration: Lease lifetime in s, m, h or d; for example 30m, 12h or 1d

  include_schema:
  - file: service/dhcp4-options.yaml.i
