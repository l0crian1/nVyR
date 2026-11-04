system:
  kind: node
  description: System settings
  children: # system

    include_schema:
    - file: system/cpu.yaml.i
    - file: system/task.yaml.i
    - file: system/login.yaml.i
    - file: system/host-name.yaml.i
    - file: system/static-host-mapping.yaml.i
    - file: system/time-zone.yaml.i
    - file: system/name-server.yaml.i
    - file: system/configuration.yaml.i
    - file: system/ntp.yaml.i
    - file: system/logging.yaml.i
