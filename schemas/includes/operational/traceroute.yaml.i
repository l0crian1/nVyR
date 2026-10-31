traceroute:
  kind: tag_node
  anchor: true
  description: Trace network hops to a destination
  command: ['traceroute.nvyr.op', 'traceroute', '@line']
  stream: true
  validators:
    regex: {pattern: '[a-zA-Z0-9:][a-zA-Z0-9_.:%-]*'}
  hints:
    host: Destination hostname
    x.x.x.x: IPv4 destination address
    x:x:x:x:x:x: IPv6 destination address (optionally with %interface)
  children: # traceroute

    include_schema:
    - file: operational/probe-vrf.yaml.i

    ipv4:
      kind: leaf_node
      description: Use IPv4 only
      valueless: true

    ipv6:
      kind: leaf_node
      description: Use IPv6 only
      valueless: true

    icmp:
      kind: leaf_node
      description: Use ICMP echo probes
      valueless: true

    tcp:
      kind: leaf_node
      description: Use TCP SYN probes
      valueless: true

    udp:
      kind: leaf_node
      description: Use UDP probes to a fixed destination port
      valueless: true

    do-not-fragment:
      kind: leaf_node
      description: Do not fragment probe packets
      valueless: true

    interface:
      kind: leaf_node
      description: Source interface for probes
      validators:
        regex: {pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'}
      hints:
        interface: Source interface name
      suggestors:
        interfaces: {}

    max-ttl:
      kind: leaf_node
      description: Maximum IP time to live or IPv6 hop limit
      validators:
        integer-range: {minimum: 1, maximum: 255}
      hints:
        1-255: Maximum hop count

    first-ttl:
      kind: leaf_node
      description: Starting IP time to live or IPv6 hop limit
      validators:
        integer-range: {minimum: 1, maximum: 255}
      hints:
        1-255: First hop to probe

    no-resolve:
      kind: leaf_node
      description: Display numeric addresses without reverse DNS lookup
      valueless: true

    port:
      kind: leaf_node
      description: Destination port or initial ICMP sequence number
      validators:
        integer-range: {minimum: 0, maximum: 65535}
      hints:
        0-65535: Port number or initial sequence number

    tos:
      kind: leaf_node
      description: Type of service or traffic class byte
      validators:
        mode: OR
        integer-range: {minimum: 0, maximum: 255}
        regex: {pattern: '0[xX][0-9a-fA-F]{1,2}'}
      hints:
        0-255: Decimal byte value; cannot be combined with dscp
        0x00-0xff: Hexadecimal byte value

    dscp:
      kind: leaf_node
      description: Differentiated services code point (sets TOS to DSCP times 4)
      validators:
        integer-range: {minimum: 0, maximum: 63}
      hints:
        0-63: DSCP value; cannot be combined with tos

    source-address:
      kind: leaf_node
      description: Source IP address for probes
      validators:
        inet-address: {}
      hints:
        x.x.x.x: Local IPv4 address
        x:x:x:x:x:x: Local IPv6 address

    mark:
      kind: leaf_node
      description: Apply a routing mark to outgoing packets
      validators:
        integer-range: {minimum: 0, maximum: 4294967295}
      hints:
        0-4294967295: Packet mark in decimal

    size:
      kind: leaf_node
      description: Total probe packet length in bytes
      validators:
        integer-range: {minimum: 0, maximum: 65000}
      hints:
        0-65000: Packet bytes (raised to the protocol minimum if smaller)

    probes:
      kind: leaf_node
      description: Number of probes per hop
      validators:
        integer-range: {minimum: 1, maximum: 10}
      hints:
        1-10: Number of probes per hop

    wait:
      kind: leaf_node
      description: Maximum seconds to wait for each probe
      validators:
        regex: {pattern: '(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)'}
      hints:
        seconds: Nonnegative timeout, such as 1 or 0.5 (maximum only)

    backward-hops:
      kind: leaf_node
      description: Estimate and display differing return-path hop counts
      valueless: true

    direct:
      kind: leaf_node
      description: Bypass routing and probe a directly connected host
      valueless: true
