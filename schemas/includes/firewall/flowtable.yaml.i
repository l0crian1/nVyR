flowtable:
  kind: tag_node
  anchor: true
  dependency: firewall-flowtable
  description: Named IPv4 and IPv6 forwarding flowtable
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Flowtable name (1-63 characters; start with a letter or underscore)
  children: # flowtable

    interface:
      kind: leaf_node
      multi: true
      depends: interface
      description: Ingress interface name or trailing prefix wildcard
      validators:
        interface-match: {}
      hints:
        name: Interface name or prefix* (matching interfaces may be created later)
      suggestors:
        interfaces: {}

    counter:
      kind: leaf_node
      valueless: true
      description: Account offloaded packets and bytes in each connection

    offload:
      kind: node
      description: Flow acceleration mode
      children: # offload

        software:
          kind: leaf_node
          valueless: true
          description: Accelerate forwarding in software without hardware offload
