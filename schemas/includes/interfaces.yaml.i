interfaces:
  kind: node
  description: Host interface configuration
  children: # interfaces

    include_schema:
    - file: interfaces/ethernet.yaml.i
    - file: interfaces/dummy.yaml.i
    - file: interfaces/loopback.yaml.i
    - file: interfaces/virtual-ethernet.yaml.i
    - file: interfaces/bridge.yaml.i
