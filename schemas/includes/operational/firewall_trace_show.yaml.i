trace:
  kind: tag_node
  optional_value: true
  anchor: true
  access: net-admin
  description: List saved traces or inspect a persistent packet capture
  command: ['firewall_trace.nvyr.op', 'show', '@line']
  timeout: 120
  validators:
    regex: {pattern: '/config/traces/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'}
  hints:
    /config/traces/file.jsonl: Saved nVyR trace capture
  children:

    id:
      kind: leaf_node
      description: Explain one packet journey in capture order
      validators:
        regex: {pattern: '[0-9a-f]{1,8}'}
      hints:
        trace-id: Hexadecimal packet trace ID from the capture index

    detail:
      kind: leaf_node
      valueless: true
      description: Include full journeys, native events and capture timestamps

    ipv4:
      kind: leaf_node
      valueless: true
      description: IPv4 packets only

    ipv6:
      kind: leaf_node
      valueless: true
      description: IPv6 packets only

    protocol:
      kind: leaf_node
      description: Filter an observed transport protocol
      choices:
        tcp: Transmission Control Protocol
        udp: User Datagram Protocol
        udplite: UDP-Lite
        sctp: Stream Control Transmission Protocol
        dccp: Datagram Congestion Control Protocol
        icmp: IPv4 Internet Control Message Protocol
        ipv6-icmp: IPv6 Internet Control Message Protocol

    source-address:
      kind: leaf_node
      description: Match an observed source address, before or after translation
      validators:
        mode: OR
        ipv4-address: {}
        ipv6-address: {}
      hints:
        address: Exact IPv4 or IPv6 source address

    destination-address:
      kind: leaf_node
      description: Match an observed destination address, before or after translation
      validators:
        mode: OR
        ipv4-address: {}
        ipv6-address: {}
      hints:
        address: Exact IPv4 or IPv6 destination address

    source-port:
      kind: leaf_node
      description: Match an observed source port
      validators:
        integer-range: {minimum: 0, maximum: 65535}
      hints:
        0-65535: Source transport port

    destination-port:
      kind: leaf_node
      description: Match an observed destination port
      validators:
        integer-range: {minimum: 0, maximum: 65535}
      hints:
        0-65535: Destination transport port

    verdict:
      kind: leaf_node
      description: Filter the last observed verdict, not end-to-end delivery
      choices:
        accept: Last observed verdict was accept
        drop: Last observed verdict was drop, including reject statements
        queue: Last observed verdict was queue
        return: Last observed verdict was return
        continue: Last observed verdict was continue

    hook:
      kind: leaf_node
      description: Require traversal of a hook identified in captured chain metadata
      choices:
        ingress: Before routing
        prerouting: Before the routing decision
        input: Traffic delivered locally
        forward: Forwarded traffic
        output: Locally generated traffic
        postrouting: After the routing decision
        egress: Device egress

    path:
      kind: leaf_node
      description: Require a captured nVyR configuration path or its descendants
      hints:
        quoted-path: 'For example "firewall ipv4 forward filter rule 10"'
