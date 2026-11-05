dns:
  kind: node
  description: DNS services
  children:

    forwarding:
      kind: node
      description: Caching DNS forwarding through Unbound
      children:

        disable:
          kind: leaf_node
          description: Disable this DNS forwarding instance
          valueless: true

        listen-address:
          kind: leaf_node
          description: Local address to receive DNS queries
          validators:
            inet-address: {}
          hints:
            IPv4|IPv6: Local address to receive DNS queries
          multi: true

        listen-interface:
          kind: leaf_node
          description: Receive DNS queries on addresses assigned to this interface
          validators:
            regex:
              pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'
          hints:
            interface: Receive DNS queries on addresses assigned to this interface
          multi: true
          depends: interface
          suggestors:
            interfaces: {}
          reapply-on-change:
          - address
          - vrf
          - disable

        port:
          kind: leaf_node
          description: Listening UDP and TCP port; defaults to 53
          validators:
            integer-range:
              minimum: 1
              maximum: 65535
          hints:
            1-65535: Listening UDP and TCP port; defaults to 53

        allow-from:
          kind: leaf_node
          description: Client prefix allowed to query this resolver
          validators:
            mode: OR
            ipv4-prefix: {}
            ipv6-prefix: {}
          hints:
            IPv4-prefix|IPv6-prefix: Client prefix allowed to query this resolver
          multi: true

        name-server:
          kind: tag_node
          description: Upstream DNS server address
          validators:
            inet-address: {}
          hints:
            IPv4|IPv6: Upstream DNS server address
          anchor: true
          children:

            port:
              kind: leaf_node
              description: Upstream port; defaults to 53, or 853 with TLS
              validators:
                integer-range:
                  minimum: 1
                  maximum: 65535
              hints:
                1-65535: Upstream port; defaults to 53, or 853 with TLS

            tls:
              kind: node
              description: Use certificate-verified DNS over TLS
              children:

                authentication-name:
                  kind: leaf_node
                  description: Expected upstream TLS certificate hostname
                  validators:
                    dns-name: {}
                  hints:
                    domain: Expected upstream TLS certificate hostname

        name-server-interface:
          kind: leaf_node
          description: Use DHCPv4, DHCPv6 and RA DNS servers learned on this interface
          validators:
            regex:
              pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'
          hints:
            interface: Use DHCPv4, DHCPv6 and RA DNS servers learned on this interface
          multi: true
          depends: interface
          suggestors:
            interfaces: {}
          reapply-on-change:
          - address
          - vrf
          - disable

        source-address:
          kind: leaf_node
          description: Local address for upstream queries
          validators:
            inet-address: {}
          hints:
            IPv4|IPv6: Local address for upstream queries
          multi: true

        domain:
          kind: tag_node
          description: DNS suffix to forward independently, including reverse zones
          validators:
            dns-name: {}
          hints:
            domain: DNS suffix to forward independently, including reverse zones
          children:

            name-server:
              kind: tag_node
              description: Upstream DNS server address
              validators:
                inet-address: {}
              hints:
                IPv4|IPv6: Upstream DNS server address
              anchor: true
              children:

                port:
                  kind: leaf_node
                  description: Upstream port; defaults to 53, or 853 with TLS
                  validators:
                    integer-range:
                      minimum: 1
                      maximum: 65535
                  hints:
                    1-65535: Upstream port; defaults to 53, or 853 with TLS

                tls:
                  kind: node
                  description: Use certificate-verified DNS over TLS
                  children:

                    authentication-name:
                      kind: leaf_node
                      description: Expected upstream TLS certificate hostname
                      validators:
                        dns-name: {}
                      hints:
                        domain: Expected upstream TLS certificate hostname

            name-server-interface:
              kind: leaf_node
              description: Use DHCPv4, DHCPv6 and RA DNS servers learned on this interface
              validators:
                regex:
                  pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'
              hints:
                interface: Use DHCPv4, DHCPv6 and RA DNS servers learned on this interface
              multi: true
              depends: interface
              suggestors:
                interfaces: {}
              reapply-on-change:
              - address
              - vrf
              - disable

            disable-cache:
              kind: leaf_node
              description: Do not cache answers for this forwarding domain
              valueless: true

            fallback-recursion:
              kind: leaf_node
              description: Try direct recursive resolution when forwarding fails
              valueless: true

        fallback-recursion:
          kind: leaf_node
          description: Try direct recursive resolution when default forwarding fails
          valueless: true

        cache:
          kind: node
          description: DNS cache resources and lifetimes
          children:

            message-size:
              kind: leaf_node
              description: Memory allocated to the DNS message cache
              validators:
                regex:
                  pattern: '[1-9][0-9]*[kKmMgG]?'
              hints:
                bytes[k|m|g]: Memory allocated to the DNS message cache

            rrset-size:
              kind: leaf_node
              description: Memory allocated to the resource record set cache
              validators:
                regex:
                  pattern: '[1-9][0-9]*[kKmMgG]?'
              hints:
                bytes[k|m|g]: Memory allocated to the resource record set cache

            minimum-ttl:
              kind: leaf_node
              description: Minimum cache lifetime in seconds
              validators:
                integer-range:
                  minimum: 0
                  maximum: 2147483647
              hints:
                0-2147483647: Minimum cache lifetime in seconds

            maximum-ttl:
              kind: leaf_node
              description: Maximum cache lifetime in seconds
              validators:
                integer-range:
                  minimum: 0
                  maximum: 2147483647
              hints:
                0-2147483647: Maximum cache lifetime in seconds

            maximum-negative-ttl:
              kind: leaf_node
              description: Maximum negative answer cache lifetime in seconds
              validators:
                integer-range:
                  minimum: 0
                  maximum: 2147483647
              hints:
                0-2147483647: Maximum negative answer cache lifetime in seconds

            prefetch:
              kind: leaf_node
              description: Refresh popular cached answers before they expire
              valueless: true

            prefetch-dnssec:
              kind: leaf_node
              description: Fetch DNSSEC keys earlier during validation
              valueless: true

            serve-expired:
              kind: node
              description: Allow stale cached answers while refreshing upstream
              children:

                maximum-age:
                  kind: leaf_node
                  description: Maximum stale age in seconds; zero means unlimited
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 2147483647
                  hints:
                    0-2147483647: Maximum stale age in seconds; zero means unlimited

                reply-ttl:
                  kind: leaf_node
                  description: TTL advertised in stale answers, in seconds
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 2147483647
                  hints:
                    0-2147483647: TTL advertised in stale answers, in seconds

                client-timeout:
                  kind: leaf_node
                  description: Milliseconds to wait for refresh before returning a stale answer
                  validators:
                    integer-range:
                      minimum: 0
                      maximum: 2147483647
                  hints:
                    0-2147483647: Milliseconds to wait for refresh before returning a stale answer
              anchor: true
          anchor: true

        dnssec:
          kind: node
          description: DNSSEC answer validation
          children:

            disable:
              kind: leaf_node
              description: Disable DNSSEC validation
              valueless: true

            insecure-domain:
              kind: leaf_node
              description: Domain exempt from DNSSEC validation
              validators:
                dns-name: {}
              hints:
                domain: Domain exempt from DNSSEC validation
              multi: true

        local-data:
          kind: node
          description: Publish managed hostnames in DNS
          children:

            static-host-mapping:
              kind: leaf_node
              description: Publish system static host mappings in this instance
              valueless: true

            dhcp-leases:
              kind: leaf_node
              description: Publish current DHCPv4 and DHCPv6 address leases from this VRF
              valueless: true

            ttl:
              kind: leaf_node
              description: TTL for published local records in seconds
              validators:
                integer-range:
                  minimum: 0
                  maximum: 2147483647
              hints:
                0-2147483647: TTL for published local records in seconds

            disable-reverse:
              kind: leaf_node
              description: Do not generate PTR records for published local addresses
              valueless: true

        options:
          kind: node
          description: Native resolver resource and response settings
          children:

            threads:
              kind: leaf_node
              description: Resolver worker threads
              validators:
                integer-range:
                  minimum: 1
                  maximum: 1024
              hints:
                1-1024: Resolver worker threads

            edns-buffer-size:
              kind: leaf_node
              description: Advertised EDNS UDP buffer size in bytes
              validators:
                integer-range:
                  minimum: 512
                  maximum: 65535
              hints:
                512-65535: Advertised EDNS UDP buffer size in bytes

            maximum-udp-size:
              kind: leaf_node
              description: Maximum UDP response size in bytes
              validators:
                integer-range:
                  minimum: 512
                  maximum: 65535
              hints:
                512-65535: Maximum UDP response size in bytes

            outgoing-range:
              kind: leaf_node
              description: Upstream UDP sockets per thread
              validators:
                integer-range:
                  minimum: 1
                  maximum: 65535
              hints:
                1-65535: Upstream UDP sockets per thread

            queries-per-thread:
              kind: leaf_node
              description: Simultaneous queries per worker thread
              validators:
                integer-range:
                  minimum: 1
                  maximum: 1048576
              hints:
                1-1048576: Simultaneous queries per worker thread

            incoming-tcp:
              kind: leaf_node
              description: Incoming TCP connections per thread
              validators:
                integer-range:
                  minimum: 0
                  maximum: 1048576
              hints:
                0-1048576: Incoming TCP connections per thread

            outgoing-tcp:
              kind: leaf_node
              description: Outgoing TCP connections per thread
              validators:
                integer-range:
                  minimum: 0
                  maximum: 1048576
              hints:
                0-1048576: Outgoing TCP connections per thread

            tcp-idle-timeout:
              kind: leaf_node
              description: Idle TCP connection timeout in milliseconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 2147483647
              hints:
                1-2147483647: Idle TCP connection timeout in milliseconds

            minimal-responses:
              kind: leaf_node
              description: Omit unnecessary authority and additional records
              valueless: true

            hide-identity:
              kind: leaf_node
              description: Refuse identity queries
              valueless: true

            hide-version:
              kind: leaf_node
              description: Refuse version queries
              valueless: true

            qname-minimisation:
              kind: node
              description: Send only necessary name labels during recursive resolution
              children:

                strict:
                  kind: leaf_node
                  description: Do not retry with the full query name when minimisation fails
                  valueless: true

        logging:
          kind: node
          description: DNS query and diagnostic logging
          children:

            verbosity:
              kind: leaf_node
              description: Native Unbound diagnostic verbosity
              validators:
                integer-range:
                  minimum: 0
                  maximum: 5
              hints:
                0-5: Native Unbound diagnostic verbosity

            queries:
              kind: leaf_node
              description: Log client DNS queries
              valueless: true

            replies:
              kind: leaf_node
              description: Log DNS replies
              valueless: true

            servfail:
              kind: leaf_node
              description: Log explanations for SERVFAIL responses
              valueless: true

            validation-failures:
              kind: leaf_node
              description: Log DNSSEC validation failures
              valueless: true
      anchor: true
      script:
        name: dns-forwarding
        priority: 57
        register:
          vrf: default
        watch:
        - interfaces
        - system static-host-mapping
        - service dhcp-server
        - service dhcpv6-server
        - vrf name * service dhcp-server
        - vrf name * service dhcpv6-server
