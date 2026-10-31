dummy:
  include_schema:
  - file: interfaces/common.yaml.i
    remove:
    - /ipv6/children/interface-identifier
  kind: tag_node
  dependency: interface
  anchor: true
  description: Dummy interface instance
  validators:
    regex: {pattern: 'dum[0-9]+'}
  suggestors:
    interfaces: {prefix: dum}
  script:
    name: dummy
    priority: 10
  hints:
    dumN: Dummy interface name
