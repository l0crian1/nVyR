firewall:
  kind: node
  description: IPv4 and IPv6 packet filtering
  script:
    name: firewall
    priority: 15
    watch:
    - vrf name * table
  children: # firewall

    include_schema:
    - file: firewall/description.yaml.i
    - file: firewall/fail-safe.yaml.i
    - file: firewall/global-options.yaml.i
    - file: firewall/flowtable.yaml.i
    - file: firewall/zone.yaml.i
    - file: firewall/zone-policy.yaml.i
    - file: firewall/group.yaml.i
    - file: firewall/ipv4.yaml.i
    - file: firewall/ipv6.yaml.i
    - file: firewall/inet.yaml.i
