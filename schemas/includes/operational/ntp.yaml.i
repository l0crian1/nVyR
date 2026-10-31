ntp:
  kind: node
  description: System clock synchronization status
  command: ['ntp.nvyr.op', 'tracking']
  children:

    clients:
      kind: node
      description: Recorded NTP clients, request counts and recent activity
      command: ['ntp.nvyr.op', 'clients']

    server:
      kind: node
      description: NTP server activity
      children:

        statistics:
          kind: node
          description: NTP serving and rate-limiting counters
          command: ['ntp.nvyr.op', 'server_statistics']
          children:

            detail:
              kind: node
              description: Include command, NTS and timestamping statistics
              command: ['ntp.nvyr.op', 'server_statistics', '--detail']

    sources:
      kind: node
      description: NTP sources, selection state, reachability and clock offsets
      command: ['ntp.nvyr.op', 'sources']
      children:

        no-resolve:
          kind: node
          description: Show source IP addresses instead of configured names
          command: ['ntp.nvyr.op', 'sources', '--no_resolve']
