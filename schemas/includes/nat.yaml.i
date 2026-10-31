nat:
  kind: node
  description: IPv4 network address translation
  script:
    name: firewall
    priority: 15
  children: # nat

    include_schema:
    - file: nat/source.yaml.i
    - file: nat/destination.yaml.i
