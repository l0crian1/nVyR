service:
  kind: node
  description: Router services
  children: # service

    include_schema:
    - file: service/ssh.yaml.i
    - file: service/dhcp-server.yaml.i
    - file: service/dhcpv6-server.yaml.i
