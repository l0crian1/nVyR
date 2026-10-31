log:
  kind: node
  description: Section-specific local logs
  command: ["logs.nvyr.op", "show", "system"]
  stream: true

  children:

    system:
      kind: node
      description: system log
      command: ["logs.nvyr.op", "show", "system"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "system", "--follow"]
          stream: true

    kernel:
      kind: node
      description: kernel log
      command: ["logs.nvyr.op", "show", "kernel"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "kernel", "--follow"]
          stream: true

    authentication:
      kind: node
      description: authentication log
      command: ["logs.nvyr.op", "show", "authentication"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "authentication", "--follow"]
          stream: true

    configd:
      kind: node
      description: configd log
      command: ["logs.nvyr.op", "show", "configd"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "configd", "--follow"]
          stream: true

    netlinkd:
      kind: node
      description: netlinkd log
      command: ["logs.nvyr.op", "show", "netlinkd"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "netlinkd", "--follow"]
          stream: true

    bgp:
      kind: node
      description: bgp log
      command: ["logs.nvyr.op", "show", "bgp"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "bgp", "--follow"]
          stream: true

    static:
      kind: node
      description: static log
      command: ["logs.nvyr.op", "show", "static"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "static", "--follow"]
          stream: true

    zebra:
      kind: node
      description: zebra log
      command: ["logs.nvyr.op", "show", "zebra"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "zebra", "--follow"]
          stream: true

    ospf:
      kind: node
      description: ospf log
      command: ["logs.nvyr.op", "show", "ospf"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "ospf", "--follow"]
          stream: true

    ntp:
      kind: node
      description: ntp log
      command: ["logs.nvyr.op", "show", "ntp"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "ntp", "--follow"]
          stream: true

    ssh:
      kind: node
      description: ssh log
      command: ["logs.nvyr.op", "show", "ssh"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "ssh", "--follow"]
          stream: true

    dhcp-server:
      kind: node
      description: dhcp-server log in the default routing instance
      command: ["logs.nvyr.op", "show", "dhcp-server"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "dhcp-server", "--follow"]
          stream: true

        vrf:
          kind: tag_node
          description: Server log in a routing instance
          hints:
            name: Configured VRF name
          command: ["logs.nvyr.op", "show", "dhcp-server", "--vrf", "@5"]
          stream: true

          children:

            follow:
              kind: node
              description: Follow new log entries until Ctrl-C
              command: ["logs.nvyr.op", "show", "dhcp-server", "--vrf", "@5", "--follow"]
              stream: true
          validators:
            regex:
              pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'
          suggestors:
            config-path:
              path: vrf name

    dhcpv6-server:
      kind: node
      description: dhcpv6-server log in the default routing instance
      command: ["logs.nvyr.op", "show", "dhcpv6-server"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "dhcpv6-server", "--follow"]
          stream: true

        vrf:
          kind: tag_node
          description: Server log in a routing instance
          hints:
            name: Configured VRF name
          command: ["logs.nvyr.op", "show", "dhcpv6-server", "--vrf", "@5"]
          stream: true

          children:

            follow:
              kind: node
              description: Follow new log entries until Ctrl-C
              command: ["logs.nvyr.op", "show", "dhcpv6-server", "--vrf", "@5", "--follow"]
              stream: true
          validators:
            regex:
              pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'
          suggestors:
            config-path:
              path: vrf name

    container:
      kind: tag_node
      description: Container application standard output and errors
      hints:
        name: Configured container name
      command: ["logs.nvyr.op", "show", "container", "--name", "@4"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "container", "--name", "@4", "--follow"]
          stream: true
      validators:
        regex:
          pattern: '[A-Za-z][A-Za-z0-9_-]{0,9}'
      suggestors:
        config-path:
          path: container name

    firewall:
      kind: node
      description: Firewall packet logs
      command: ["logs.nvyr.op", "show", "firewall"]
      stream: true

      children:

        follow:
          kind: node
          description: Follow new log entries until Ctrl-C
          command: ["logs.nvyr.op", "show", "firewall", "--follow"]
          stream: true

        group:
          kind: tag_node
          description: Named NFLOG collector
          hints:
            name: Configured log-group name
          command: ["logs.nvyr.op", "show", "firewall", "--group", "@5"]
          stream: true

          children:

            follow:
              kind: node
              description: Follow new log entries until Ctrl-C
              command: ["logs.nvyr.op", "show", "firewall", "--group", "@5", "--follow"]
              stream: true
          validators:
            regex:
              pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'
          suggestors:
            config-path:
              path: firewall group log-group

        ipv4:
          kind: node
          description: IPv4 packet logs
          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4"]
          stream: true

          children:

            follow:
              kind: node
              description: Follow new log entries until Ctrl-C
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--follow"]
              stream: true

            input:
              kind: node
              description: input packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "input"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "input", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "input", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "input", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "input", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "input", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv4 input filter rule

            ingress:
              kind: node
              description: ingress packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "ingress"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "ingress", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "ingress", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "ingress", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "ingress", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "ingress", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv4 ingress filter rule

            forward:
              kind: node
              description: forward packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "forward"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "forward", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "forward", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "forward", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "forward", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "forward", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv4 forward filter rule

            output:
              kind: node
              description: output packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv4 output filter rule

                raw:
                  kind: node
                  description: raw packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output", "--stage", "raw"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output", "--stage", "raw", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output", "--stage", "raw", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "output", "--stage", "raw", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv4 output raw rule

            prerouting:
              kind: node
              description: prerouting packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "prerouting"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "prerouting", "--follow"]
                  stream: true

                raw:
                  kind: node
                  description: raw packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "prerouting", "--stage", "raw"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "prerouting", "--stage", "raw", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "prerouting", "--stage", "raw", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--hook", "prerouting", "--stage", "raw", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv4 prerouting raw rule

            name:
              kind: tag_node
              description: Named chain logs
              hints:
                name: Configured named firewall chain
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--chain", "@6"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--chain", "@6", "--follow"]
                  stream: true

                rule:
                  kind: tag_node
                  description: Logs from one named-chain rule
                  hints:
                    1-999999: Rule number within this named chain
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--chain", "@6", "--rule", "@8"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv4", "--chain", "@6", "--rule", "@8", "--follow"]
                      stream: true
                  validators:
                    integer-range:
                      minimum: 1
                      maximum: 999999
              validators:
                regex:
                  pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'
              suggestors:
                config-path:
                  path: firewall ipv4 name

        inet:
          kind: node
          description: Family-neutral packet logs
          command: ["logs.nvyr.op", "show", "firewall", "--family", "inet"]
          stream: true

          children:

            follow:
              kind: node
              description: Follow new log entries until Ctrl-C
              command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--follow"]
              stream: true

            input:
              kind: node
              description: input packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "input"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "input", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "input", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "input", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "input", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "input", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall inet input filter rule

            ingress:
              kind: node
              description: ingress packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "ingress"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "ingress", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "ingress", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "ingress", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "ingress", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "ingress", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall inet ingress filter rule

            forward:
              kind: node
              description: forward packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "forward"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "forward", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "forward", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "forward", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "forward", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "forward", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall inet forward filter rule

            output:
              kind: node
              description: output packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall inet output filter rule

                raw:
                  kind: node
                  description: raw packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output", "--stage", "raw"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output", "--stage", "raw", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output", "--stage", "raw", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "output", "--stage", "raw", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall inet output raw rule

            prerouting:
              kind: node
              description: prerouting packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "prerouting"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "prerouting", "--follow"]
                  stream: true

                raw:
                  kind: node
                  description: raw packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "prerouting", "--stage", "raw"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "prerouting", "--stage", "raw", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "prerouting", "--stage", "raw", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--hook", "prerouting", "--stage", "raw", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall inet prerouting raw rule

            name:
              kind: tag_node
              description: Named chain logs
              hints:
                name: Configured named firewall chain
              command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--chain", "@6"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--chain", "@6", "--follow"]
                  stream: true

                rule:
                  kind: tag_node
                  description: Logs from one named-chain rule
                  hints:
                    1-999999: Rule number within this named chain
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--chain", "@6", "--rule", "@8"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "inet", "--chain", "@6", "--rule", "@8", "--follow"]
                      stream: true
                  validators:
                    integer-range:
                      minimum: 1
                      maximum: 999999
              validators:
                regex:
                  pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'
              suggestors:
                config-path:
                  path: firewall inet name

        ipv6:
          kind: node
          description: IPv6 packet logs
          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6"]
          stream: true

          children:

            follow:
              kind: node
              description: Follow new log entries until Ctrl-C
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--follow"]
              stream: true

            input:
              kind: node
              description: input packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "input"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "input", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "input", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "input", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "input", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "input", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv6 input filter rule

            ingress:
              kind: node
              description: ingress packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "ingress"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "ingress", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "ingress", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "ingress", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "ingress", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "ingress", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv6 ingress filter rule

            forward:
              kind: node
              description: forward packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "forward"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "forward", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "forward", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "forward", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "forward", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "forward", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv6 forward filter rule

            output:
              kind: node
              description: output packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output", "--follow"]
                  stream: true

                filter:
                  kind: node
                  description: filter packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output", "--stage", "filter"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output", "--stage", "filter", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output", "--stage", "filter", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output", "--stage", "filter", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv6 output filter rule

                raw:
                  kind: node
                  description: raw packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output", "--stage", "raw"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output", "--stage", "raw", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output", "--stage", "raw", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "output", "--stage", "raw", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv6 output raw rule

            prerouting:
              kind: node
              description: prerouting packet logs
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "prerouting"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "prerouting", "--follow"]
                  stream: true

                raw:
                  kind: node
                  description: raw packet logs
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "prerouting", "--stage", "raw"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "prerouting", "--stage", "raw", "--follow"]
                      stream: true

                    rule:
                      kind: tag_node
                      description: Logs from one exact rule
                      hints:
                        1-999999: Firewall rule number
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "prerouting", "--stage", "raw", "--rule", "@8"]
                      stream: true

                      children:

                        follow:
                          kind: node
                          description: Follow new log entries until Ctrl-C
                          command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--hook", "prerouting", "--stage", "raw", "--rule", "@8", "--follow"]
                          stream: true
                      validators:
                        integer-range:
                          minimum: 1
                          maximum: 999999
                      suggestors:
                        config-path:
                          path: firewall ipv6 prerouting raw rule

            name:
              kind: tag_node
              description: Named chain logs
              hints:
                name: Configured named firewall chain
              command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--chain", "@6"]
              stream: true

              children:

                follow:
                  kind: node
                  description: Follow new log entries until Ctrl-C
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--chain", "@6", "--follow"]
                  stream: true

                rule:
                  kind: tag_node
                  description: Logs from one named-chain rule
                  hints:
                    1-999999: Rule number within this named chain
                  command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--chain", "@6", "--rule", "@8"]
                  stream: true

                  children:

                    follow:
                      kind: node
                      description: Follow new log entries until Ctrl-C
                      command: ["logs.nvyr.op", "show", "firewall", "--family", "ipv6", "--chain", "@6", "--rule", "@8", "--follow"]
                      stream: true
                  validators:
                    integer-range:
                      minimum: 1
                      maximum: 999999
              validators:
                regex:
                  pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'
              suggestors:
                config-path:
                  path: firewall ipv6 name

    follow:
      kind: node
      description: Follow new log entries until Ctrl-C
      command: ["logs.nvyr.op", "show", "system", "--follow"]
      stream: true

    nat:
      kind: node
      description: Source and destination NAT packet logs
      command: ['logs.nvyr.op', 'show', 'nat']
      stream: true
      children:

        follow:
          kind: node
          description: Follow new NAT packet logs
          command: ['logs.nvyr.op', 'show', 'nat', '--follow']
          stream: true

        source:
          kind: node
          description: Source NAT packet logs
          command: ['logs.nvyr.op', 'show', 'nat', '--direction', 'source']
          stream: true
          children:

            follow:
              kind: node
              description: Follow new packet logs
              command: ['logs.nvyr.op', 'show', 'nat', '--direction', 'source', '--follow']
              stream: true

            rule:
              kind: tag_node
              description: Logs from one exact NAT rule
              hints:
                1-999999: NAT rule number
              validators:
                integer-range: {minimum: 1, maximum: 999999}
              command: ['logs.nvyr.op', 'show', 'nat', '--direction', 'source', '--rule', '@6']
              stream: true
              children:

                follow:
                  kind: node
                  description: Follow new packet logs
                  command: ['logs.nvyr.op', 'show', 'nat', '--direction', 'source', '--rule', '@6', '--follow']
                  stream: true

        destination:
          kind: node
          description: Destination NAT packet logs
          command: ['logs.nvyr.op', 'show', 'nat', '--direction', 'destination']
          stream: true
          children:

            follow:
              kind: node
              description: Follow new packet logs
              command: ['logs.nvyr.op', 'show', 'nat', '--direction', 'destination', '--follow']
              stream: true

            rule:
              kind: tag_node
              description: Logs from one exact NAT rule
              hints:
                1-999999: NAT rule number
              validators:
                integer-range: {minimum: 1, maximum: 999999}
              command: ['logs.nvyr.op', 'show', 'nat', '--direction', 'destination', '--rule', '@6']
              stream: true
              children:

                follow:
                  kind: node
                  description: Follow new packet logs
                  command: ['logs.nvyr.op', 'show', 'nat', '--direction', 'destination', '--rule', '@6', '--follow']
                  stream: true
