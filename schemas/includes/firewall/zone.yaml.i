zone:
  kind: tag_node
  anchor: true
  dependency: firewall-zone
  description: Interface security zone
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Zone name
  children:

    description:
      kind: leaf_node
      description: Zone description
      hints:
        text: Zone description; quote spaces; at most 128 characters
      validators:
        length: {maximum: 128}

    interface:
      kind: leaf_node
      multi: true
      depends: interface
      description: Zone member interface; VRF master devices are not allowed
      validators:
        interface-match: {}
      hints:
        name: Interface name
        prefix*: Claim interface names starting with this prefix
      suggestors:
        interfaces: {}

    local-zone:
      kind: leaf_node
      valueless: true
      description: Represent traffic to and from this router

    default-action:
      kind: leaf_node
      description: Verdict for traffic to this zone without an assigned family policy
      choices:
        accept: Accept traffic
        drop: Silently drop traffic
      validators:
        list: {values: accept drop}
      default: {mode: direct, value: drop}

    intra-zone:
      kind: node
      anchor: true
      description: Policy between interfaces in this zone
      children:

        default-action:
          kind: leaf_node
          description: Verdict when no intra-zone policy is assigned for the family
          choices:
            accept: Accept traffic
            drop: Silently drop traffic
          validators:
            list: {values: accept drop}
          default: {mode: direct, value: accept}

        include_schema:
        - file: firewall/zone-policies.yaml.i
          as: null
