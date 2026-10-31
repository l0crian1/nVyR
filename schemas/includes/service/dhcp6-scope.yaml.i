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

  preferred-lifetime:
    kind: leaf_node
    description: Time before a leased IPv6 address becomes deprecated; use s, m, h or d
    validators:
      duration:
        maximum: 4294967294
    hints:
      duration: Preferred lifetime in s, m, h or d; for example 30m, 12h or 1d

  valid-lifetime:
    kind: leaf_node
    description: Time before a leased IPv6 address expires; use s, m, h or d
    validators:
      duration:
        maximum: 4294967294
    hints:
      duration: Valid lifetime in s, m, h or d; for example 30m, 12h or 1d

  include_schema:
  - file: service/dhcp6-options.yaml.i
