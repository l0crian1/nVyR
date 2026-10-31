zone-policy:
  kind: node
  description: Directional policies between security zones
  children:

    from-zone:
      kind: tag_node
      depends: firewall-zone
      description: Source security zone
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Source zone name
      suggestors:
        config-path: {path: 'firewall zone'}
      children:

        to-zone:
          kind: tag_node
          anchor: true
          depends: firewall-zone
          description: Destination security zone
          validators:
            regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
          hints:
            name: Destination zone name
          suggestors:
            config-path: {path: 'firewall zone'}
          children:

            include_schema:
            - file: firewall/zone-policies.yaml.i
              as: null
