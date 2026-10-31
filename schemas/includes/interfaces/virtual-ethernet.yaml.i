virtual-ethernet:
  include_schema:
  - file: interfaces/common.yaml.i
    add:
      /vif:
        include_schema:
        - file: interfaces/vif.yaml.i
          as: null
      /peer-name:
        kind: leaf_node
        description: Other configured endpoint; both endpoints must name each other
        validators:
          regex: {pattern: 'veth[0-9]{1,11}'}
        suggestors:
          config-path: {path: 'interfaces virtual-ethernet'}
        hints:
          vethN: Peer virtual Ethernet interface name
  kind: tag_node
  dependency: interface
  anchor: true
  description: Virtual Ethernet pair endpoint
  validators:
    regex: {pattern: 'veth[0-9]{1,11}'}
  suggestors:
    interfaces: {prefix: veth}
  script:
    name: virtual-ethernet
    priority: 10
  hints:
    vethN: Virtual Ethernet interface name
