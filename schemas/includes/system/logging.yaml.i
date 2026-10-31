logging:
  kind: node
  anchor: true
  description: Local log severity and shared file rotation
  script:
    name: logging
    priority: 1
  children:

    level:
      kind: leaf_node
      description: Least severe system message retained (default info)
      choices:
        emerg: System unusable
        alert: Immediate action required
        crit: Critical conditions
        err: Errors
        warn: Warnings
        notice: Normal but significant events
        info: Informational messages
        debug: Debugging details
      validators:
        list: {values: 'emerg alert crit err warn notice info debug'}

    rotation:
      kind: node
      anchor: true
      description: Rotation shared by all local log files
      children:

        size:
          kind: leaf_node
          description: Rotate files at this size; checked each minute (default 25m)
          validators:
            regex: {pattern: '[1-9][0-9]{0,5}[kmg]'}
          hints:
            size: Size in k, m or g (powers of 1024)

        count:
          kind: leaf_node
          description: Number of rotated archives retained (default 10)
          hints:
            1-1000: Number of rotated archives retained (default 10)
          validators:
            integer-range: {minimum: 1, maximum: 1000}

    service:
      kind: tag_node
      anchor: true
      description: Override the global threshold for a service
      choices:
        system: General system services
        kernel: Linux kernel messages
        authentication: Login, authentication and privilege changes
        configd: Configuration daemon
        netlinkd: Interface management daemon
        bgp: FRRouting BGP daemon
        static: FRRouting static routing daemon
        zebra: FRRouting routing manager
        ospf: FRRouting OSPF daemon
        dhcp-server: Kea DHCPv4 servers
        dhcpv6-server: Kea DHCPv6 servers
        ntp: Chrony time service
        ssh: Secure Shell service
      validators:
        list: {values: 'system kernel authentication configd netlinkd bgp static zebra ospf dhcp-server dhcpv6-server ntp ssh'}
      children:

        level:
          kind: leaf_node
          description: Least severe message retained for this service
          choices:
            emerg: System unusable
            alert: Immediate action required
            crit: Critical conditions
            err: Errors
            warn: Warnings
            notice: Normal but significant events
            info: Informational messages
            debug: Debugging details
          validators:
            list: {values: 'emerg alert crit err warn notice info debug'}
