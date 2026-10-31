ssh:
  kind: node
  description: Secure Shell service
  script:
    name: ssh
    priority: 50
    watch: [system logging]
  children: # ssh

    listen-address:
      kind: leaf_node
      strip_kind: ip
      description: Local addresses on which SSH listens (all addresses when omitted)
      validators:
        inet-address: {}
      hints:
        x.x.x.x: Local IPv4 address
        x:x:x:x:x:x: Local IPv6 address
      multi: true
