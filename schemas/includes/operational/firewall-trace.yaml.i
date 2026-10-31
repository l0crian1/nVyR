monitor:
  kind: node
  description: Watch live system events
  children:

    firewall:
      kind: node
      description: Watch firewall events
      children:

        trace:
          kind: node
          anchor: true
          access: net-admin
          description: Watch packets selected by configured nftrace rules
          command: ['firewall_trace.nvyr.op', 'monitor', '@line']
          stream: true
          children:

            duration:
              kind: leaf_node
              description: Stop monitoring after this duration; tracing rules remain enabled
              validators:
                duration: {maximum: 2147483647}
              hints:
                time: Positive duration in s, m, h or d, for example 30s or 2m

            save:
              kind: leaf_node
              description: Save JSON Lines events to a new persistent trace file
              validators:
                regex: {pattern: '/config/traces/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'}
              hints:
                /config/traces/file.jsonl: New file; existing files are never overwritten
