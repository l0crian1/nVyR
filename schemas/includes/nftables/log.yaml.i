log:
  kind: node
  anchor: true
  description: Log matching packets to the kernel log or an NFLOG group
  children: # log

    level:
      kind: leaf_node
      description: Syslog severity (default warn)
      validators:
        list: {values: 'emerg alert crit err warn notice info debug'}
      choices:
        emerg: System is unusable
        alert: Immediate action needed
        crit: Critical condition
        err: Error condition
        warn: Warning condition (default)
        notice: Normal but significant condition
        info: Informational message
        debug: Debugging message

    flags:
      kind: leaf_node
      joinable: true
      description: Additional packet details to include in the log
      validators:
        log-flags: {}
      choices:
        tcp-sequence: TCP sequence numbers
        tcp-options: TCP options
        ip-options: IP options
        skuid: UID of the originating socket
        ether: Ethernet header
        all: All supported details

    group:
      kind: leaf_node
      description: Send packets to a named NFLOG collector
      depends: firewall-log-group
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      suggestors:
        config-path: {path: 'firewall group log-group'}
      hints:
        name: Configured log group
