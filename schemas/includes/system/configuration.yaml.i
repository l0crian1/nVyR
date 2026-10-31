configuration:
  kind: node
  description: Configuration management settings
  script:
    name: configuration
    priority: 30
  children: # configuration

    commit-revisions:
      kind: leaf_node
      description: Maximum number of retained configuration revisions
      validators:
        positive-integer: {}
      hints:
        number: Number of revisions to retain, including the current revision
      default:
        mode: always
        value: '20'
