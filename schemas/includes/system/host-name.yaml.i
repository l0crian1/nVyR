host-name:
  kind: leaf_node
  strip_kind: private
  description: System host name
  hints:
    hostname: Router hostname, 1-15 characters; start with a letter
  script:
    name: system
    priority: 30
  validators:
    regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
