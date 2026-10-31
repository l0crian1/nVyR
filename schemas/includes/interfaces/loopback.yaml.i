loopback:
  kind: tag_node
  dependency: interface
  anchor: true
  description: System loopback interface
  validators:
    list: {values: lo}
  choices:
    lo: System loopback interface
  script:
    name: loopback
    priority: 10
  children:

    include_schema:
    - file: interfaces/address.yaml.i
    - file: generic/description.yaml.i
      replace:
        /description: Linux interface alias
        /hints:
          text: Interface description; quote spaces
      add:
        /validators:
          interface-description: {}
