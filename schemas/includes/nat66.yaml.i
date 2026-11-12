nat66:
  kind: node
  description: IPv6 network address translation
  script:
    name: firewall
    priority: 6
  children: # nat66

    include_schema:
    - file: nat/source6.yaml.i
    - file: nat/destination6.yaml.i
