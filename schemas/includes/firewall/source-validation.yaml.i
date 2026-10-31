source-validation:
  kind: node
  anchor: true
  description: Validate incoming source addresses against reverse routes
  children:

    default:
      kind: leaf_node
      description: Source validation for interfaces without an override
      default:
        mode: direct
        value: disabled
      choices:
        strict: Require the reverse route to use the receiving interface
        loose: Require a usable reverse route through any interface
        disabled: Do not perform automatic source validation
      validators:
        list: {values: strict loose disabled}

    interface:
      kind: tag_node
      anchor: true
      depends: interface
      description: Override source validation for an incoming interface
      validators:
        regex: {pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'}
      hints:
        name: Incoming interface name (up to 15 characters)
      suggestors:
        interfaces: {}
      children:

        mode:
          kind: leaf_node
          description: Source validation override; must differ from the global default
          choices:
            strict: Require the reverse route to use this interface
            loose: Require a usable reverse route through any interface
            disabled: Skip source validation on this interface
          validators:
            list: {values: strict loose disabled}
