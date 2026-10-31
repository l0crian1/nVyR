ping:
  kind: tag_node
  anchor: true
  description: Send ICMP echo requests
  command: ['ping.nvyr.op', 'ping', '@line']
  stream: true
  validators:
    regex: {pattern: '[a-zA-Z0-9:][a-zA-Z0-9_.:%-]*'}
  hints:
    host: Destination hostname
    x.x.x.x: IPv4 destination address
    x:x:x:x:x:x: IPv6 destination address (optionally with %interface)
  children: # ping

    include_schema:
    - file: operational/probe-vrf.yaml.i

    adaptive:
      kind: leaf_node
      description: Adapt the probe interval to round-trip time
      valueless: true

    allow-broadcast:
      kind: leaf_node
      description: Allow probes to a broadcast address
      valueless: true

    audible:
      kind: leaf_node
      description: Sound a bell for each reply
      valueless: true

    bypass-route:
      kind: leaf_node
      description: Bypass routing and probe a directly connected host
      valueless: true

    count:
      kind: leaf_node
      description: Number of echo requests to send
      validators:
        positive-integer: {}
      hints:
        count: Positive number of probes

    deadline:
      kind: leaf_node
      description: Stop after this many seconds
      validators:
        nonnegative-integer: {}
      hints:
        seconds: Deadline in whole seconds (0 for no deadline)

    do-not-fragment:
      kind: leaf_node
      description: Require packets to fit the path MTU without fragmentation
      valueless: true

    dscp:
      kind: leaf_node
      description: Differentiated services code point (sets TOS to DSCP times 4)
      validators:
        integer-range: {minimum: 0, maximum: 63}
      hints:
        0-63: DSCP value; cannot be combined with tos

    flood:
      kind: leaf_node
      description: Send probes as fast as allowed
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

    interval:
      kind: leaf_node
      description: Seconds between probes
      validators:
        regex: {pattern: '(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)'}
      hints:
        seconds: Nonnegative interval, such as 0.5 or .01

    ipv4:
      kind: leaf_node
      description: Use IPv4 only
      valueless: true

    ipv6:
      kind: leaf_node
      description: Use IPv6 only
      valueless: true

    mark:
      kind: leaf_node
      description: Apply a routing mark to outgoing packets
      validators:
        integer-range: {minimum: 0, maximum: 4294967295}
      hints:
        0-4294967295: Packet mark in decimal

    no-loopback:
      kind: leaf_node
      description: Suppress multicast loopback
      valueless: true

    numeric:
      kind: leaf_node
      description: Display numeric addresses without reverse DNS lookup
      valueless: true

    pattern:
      kind: leaf_node
      description: Hexadecimal pattern to fill the payload
      validators:
        regex: {pattern: '[0-9a-fA-F]{1,32}'}
      hints:
        hex: Up to 32 hexadecimal digits (16 bytes)

    quiet:
      kind: leaf_node
      description: Display only startup and summary output
      valueless: true

    record-route:
      kind: leaf_node
      description: Record the IPv4 route in probe packets
      valueless: true

    size:
      kind: leaf_node
      description: Number of payload bytes per probe
      validators:
        integer-range: {minimum: 0, maximum: 65527}
      hints:
        0-65527: Payload bytes (the address family may impose a smaller limit)

    source-address:
      kind: leaf_node
      description: Source IP address for probes
      validators:
        inet-address: {}
      hints:
        x.x.x.x: Local IPv4 address
        x:x:x:x:x:x: Local IPv6 address

    timestamp:
      kind: leaf_node
      description: Print a timestamp before each output line
      valueless: true

    tos:
      kind: leaf_node
      description: Type of service or traffic class byte
      validators:
        mode: OR
        integer-range: {minimum: 0, maximum: 255}
        regex: {pattern: '0[xX][0-9a-fA-F]{1,2}'}
      hints:
        0-255: Decimal byte value
        0x00-0xff: Hexadecimal byte value

    ttl:
      kind: leaf_node
      description: IP time to live or IPv6 hop limit
      validators:
        integer-range: {minimum: 1, maximum: 255}
      hints:
        1-255: Maximum hop count

    verbose:
      kind: leaf_node
      description: Display verbose diagnostics
      valueless: true
