parameters:
  kind: node
  description: General BGP behavior and defaults
  anchor: true
  children:

    allow-martian-nexthop:
      kind: leaf_node
      description: Accept otherwise invalid next-hop addresses
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: disable
        mode: direct

    client-to-client:
      kind: node
      description: Route reflection between clients
      anchor: true
      children:

        reflection:
          kind: leaf_node
          description: Reflect routes between route-reflector clients
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: enable
            mode: direct

    ebgp-connected-route-check:
      kind: leaf_node
      description: Require directly connected next hops for single-hop eBGP
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: enable
        mode: direct

    ebgp-requires-policy:
      kind: leaf_node
      description: Require inbound and outbound policies for eBGP
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: disable
        mode: direct

    enforce-first-as:
      kind: leaf_node
      description: Require the first received AS to match the eBGP neighbor
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: enable
        mode: direct

    fast-convergence:
      kind: leaf_node
      description: Accelerate BGP convergence
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: disable
        mode: direct

    fast-external-failover:
      kind: leaf_node
      description: Reset directly connected external sessions immediately on link failure
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: enable
        mode: direct

    graceful-shutdown:
      kind: leaf_node
      description: Advertise graceful shutdown before maintenance
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: disable
        mode: direct

    hard-administrative-reset:
      kind: leaf_node
      description: Send hard-reset CEASE for administrative resets
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: enable
        mode: direct

    ipv6-auto-ra:
      kind: leaf_node
      description: Allow BGP to request IPv6 router advertisements
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: enable
        mode: direct

    log-neighbor-changes:
      kind: leaf_node
      description: Log neighbor state changes and reset reasons
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: disable
        mode: direct

    reject-as-sets:
      kind: leaf_node
      description: Reject AS_SET and AS_CONFED_SET paths
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: disable
        mode: direct

    shutdown:
      kind: leaf_node
      description: Administratively shut down this BGP instance
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: disable
        mode: direct

    suppress-duplicates:
      kind: leaf_node
      description: Suppress identical route updates
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: enable
        mode: direct

    default:
      kind: node
      description: Defaults for BGP neighbors and route selection
      anchor: true
      children:

        ipv4-unicast:
          kind: leaf_node
          description: Activate IPv4 unicast for neighbors by default
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        ipv6-unicast:
          kind: leaf_node
          description: Activate IPv6 unicast for neighbors by default
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        show-hostname:
          kind: leaf_node
          description: Display advertised peer hostnames
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        show-nexthop-hostname:
          kind: leaf_node
          description: Display next-hop hostnames
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        dynamic-capability:
          kind: leaf_node
          description: Enable dynamic capability negotiation by default
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        link-local-capability:
          kind: leaf_node
          description: Enable IPv6 link-local capability by default
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        shutdown:
          kind: leaf_node
          description: Shut down neighbors by default
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        local-preference:
          kind: leaf_node
          description: Default local preference for received routes
          validators:
            integer-range:
              minimum: 0
              maximum: 4294967295
          hints:
            0-4294967295: Default local preference for received routes
          default:
            value: '100'
            mode: direct

        subgroup-pkt-queue-max:
          kind: leaf_node
          description: Maximum packets queued per update subgroup
          validators:
            integer-range:
              minimum: 20
              maximum: 100
          hints:
            20-100: Maximum packets queued per update subgroup
          default:
            value: '40'
            mode: direct

        software-version-capability:
          kind: leaf_node
          description: Software version capability encoding
          validators:
            list:
              values: disable legacy
          choices:
            disable: Do not advertise the capability
            legacy: Use legacy capability encoding
          default:
            value: disable
            mode: direct

    network:
      kind: node
      description: Conditions for originating configured BGP networks
      anchor: true
      children:

        import-check:
          kind: leaf_node
          description: Require an exact route before advertising a configured network
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

    route-reflector:
      kind: node
      description: Route reflector settings
      anchor: true
      children:

        allow-outbound-policy:
          kind: leaf_node
          description: Allow outbound route-map attribute changes on reflected routes
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

    bestpath:
      kind: node
      description: BGP best-path selection
      anchor: true
      children:

        aigp:
          kind: leaf_node
          description: Compare accumulated IGP metrics during best-path selection
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        compare-routerid:
          kind: leaf_node
          description: Compare router IDs instead of preferring the oldest external path
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        as-path:
          kind: node
          description: AS-path comparison during best-path selection
          anchor: true
          children:

            ignore:
              kind: leaf_node
              description: Ignore AS-path length during best-path selection
              validators:
                list:
                  values: enable disable
              choices:
                enable: Enable this behavior
                disable: Disable this behavior
              default:
                value: disable
                mode: direct

            confed:
              kind: leaf_node
              description: Include confederation ASes in AS-path length
              validators:
                list:
                  values: enable disable
              choices:
                enable: Enable this behavior
                disable: Disable this behavior
              default:
                value: disable
                mode: direct

            multipath-relax:
              kind: leaf_node
              description: Allow multipath through different neighboring ASes
              validators:
                list:
                  values: enable disable
              choices:
                enable: Enable this behavior
                disable: Disable this behavior
              default:
                value: disable
                mode: direct

            multipath-relax-as-set:
              kind: leaf_node
              description: Combine multipath ASes into an AS_SET
              validators:
                list:
                  values: enable disable
              choices:
                enable: Enable this behavior
                disable: Disable this behavior
              default:
                value: disable
                mode: direct

        peer-type:
          kind: node
          description: Multipath across internal and external BGP peers
          anchor: true
          children:

            multipath-relax:
              kind: leaf_node
              description: Allow multipath across different peer types
              validators:
                list:
                  values: enable disable
              choices:
                enable: Enable this behavior
                disable: Disable this behavior
              default:
                value: disable
                mode: direct

        med:
          kind: node
          description: Multi-exit discriminator (MED) comparison
          anchor: true
          children:

            confed:
              kind: leaf_node
              description: Compare MED across confederation peers
              validators:
                list:
                  values: enable disable
              choices:
                enable: Enable this behavior
                disable: Disable this behavior
              default:
                value: disable
                mode: direct

            missing-as-worst:
              kind: leaf_node
              description: Treat missing MED as the worst value
              validators:
                list:
                  values: enable disable
              choices:
                enable: Enable this behavior
                disable: Disable this behavior
              default:
                value: disable
                mode: direct

        bandwidth:
          kind: leaf_node
          description: Unequal-cost multipath bandwidth handling
          validators:
            list:
              values: ecmp skip-missing default-weight-for-missing ignore
          choices:
            ecmp: Use equal-cost multipath
            skip-missing: Exclude paths without bandwidth
            default-weight-for-missing: Assign default weight to paths without bandwidth
            ignore: Ignore bandwidth for weighting
          default:
            value: ecmp
            mode: direct

    graceful-restart:
      kind: node
      description: Graceful restart settings
      anchor: true
      children:

        notification:
          kind: leaf_node
          description: Negotiate graceful restart notification support
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: enable
            mode: direct

        preserve-fw-state:
          kind: leaf_node
          description: Advertise preserved forwarding state after restart
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: disable
            mode: direct

        end-of-rib:
          kind: leaf_node
          description: Send end-of-RIB markers
          validators:
            list:
              values: enable disable
          choices:
            enable: Enable this behavior
            disable: Disable this behavior
          default:
            value: enable
            mode: direct

        mode:
          kind: leaf_node
          description: Graceful restart role
          validators:
            list:
              values: helper restart disable
          choices:
            helper: Retain routes for restarting peers
            restart: Advertise restart capability and assist restarting peers
            disable: Disable graceful restart
          default:
            value: helper
            mode: direct

        restart-time:
          kind: leaf_node
          description: Advertised restart time in seconds
          validators:
            integer-range:
              minimum: 0
              maximum: 4095
          hints:
            0-4095: Advertised restart time in seconds
          default:
            value: '120'
            mode: direct

        stalepath-time:
          kind: leaf_node
          description: Stale path retention time in seconds
          validators:
            integer-range:
              minimum: 1
              maximum: 4095
          hints:
            1-4095: Stale path retention time in seconds
          default:
            value: '360'
            mode: direct

        select-defer-time:
          kind: leaf_node
          description: Best-path selection deferral in seconds
          validators:
            integer-range:
              minimum: 0
              maximum: 3600
          hints:
            0-3600: Best-path selection deferral in seconds
          default:
            value: '120'
            mode: direct

        rib-stale-time:
          kind: leaf_node
          description: Stale RIB retention time in seconds
          validators:
            integer-range:
              minimum: 1
              maximum: 3600
          hints:
            1-3600: Stale RIB retention time in seconds
          default:
            value: '500'
            mode: direct

    router-id:
      kind: leaf_node
      description: BGP router identifier
      validators:
        bgp-router-id: {}
      hints:
        x.x.x.x: Nonzero unicast IPv4 router identifier

    timers:
      kind: node
      description: Default session timers
      anchor: true
      children:

        keepalive:
          kind: leaf_node
          description: Keepalive interval in seconds
          validators:
            integer-range:
              minimum: 0
              maximum: 65535
          hints:
            0-65535: Keepalive interval in seconds

        holdtime:
          kind: leaf_node
          description: Hold time in seconds; zero disables the hold timer
          validators:
            integer-ranges: {ranges: [[0, 0], [3, 65535]]}
          hints:
            0 or 3-65535: Hold time in seconds; zero disables the hold timer

    cluster-id:
      kind: leaf_node
      description: Route-reflector cluster identifier
      validators:
        ipv4-address: {}
      hints:
        x.x.x.x: Cluster identifier

    confederation:
      kind: node
      description: Confederation settings
      anchor: true
      children:

        identifier:
          kind: leaf_node
          description: Public confederation autonomous system number
          validators:
            integer-range:
              minimum: 1
              maximum: 4294967295
          hints:
            1-4294967295: Public confederation autonomous system number

        peers:
          kind: leaf_node
          description: Other member autonomous systems
          validators:
            integer-range:
              minimum: 1
              maximum: 4294967295
          hints:
            1-4294967295: Other member autonomous systems
          multi: true

    conditional-advertisement:
      kind: node
      description: Conditional advertisement settings
      anchor: true
      children:

        timer:
          kind: leaf_node
          description: Conditional advertisement scan interval in seconds
          validators:
            integer-range:
              minimum: 5
              maximum: 240
          hints:
            5-240: Conditional advertisement scan interval in seconds
          default:
            value: '60'
            mode: direct

    long-lived-graceful-restart:
      kind: node
      description: Long-lived graceful restart and stale-route retention
      anchor: true
      children:

        stale-time:
          kind: leaf_node
          description: Long-lived stale path time in seconds; zero disables
          validators:
            integer-range:
              minimum: 0
              maximum: 16777215
          hints:
            0-16777215: Long-lived stale path time in seconds; zero disables
          default:
            value: '0'
            mode: direct

    listen:
      kind: node
      description: Dynamic BGP neighbors
      anchor: true
      children:

        limit:
          kind: leaf_node
          description: Maximum dynamic neighbors in this instance
          validators:
            integer-range:
              minimum: 1
              maximum: 65535
          hints:
            1-65535: Maximum dynamic neighbors in this instance
          default:
            value: '100'
            mode: direct

        range:
          kind: tag_node
          description: Allow dynamic neighbors from this prefix
          anchor: true
          validators:
            bgp-listen-prefix: {}
          hints:
            prefix: IPv4 or IPv6 network prefix
          children:

            peer-group:
              kind: leaf_node
              description: Peer-group assigned to matching dynamic neighbors
              validators:
                regex:
                  pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
              hints:
                name: Peer-group in this BGP instance

    minimum-holdtime:
      kind: leaf_node
      description: Minimum accepted neighbor hold time; zero disables; 180 unavailable in FRR 10.7.1
      validators:
        integer-ranges: {ranges: [[0, 179], [181, 65535]]}
      hints:
        0-179 or 181-65535: Minimum accepted neighbor hold time; zero disables; 180 unavailable in FRR 10.7.1
      default:
        value: '0'
        mode: direct

    route-map:
      kind: node
      description: Reevaluation after routing-policy changes
      anchor: true
      children:

        delay-timer:
          kind: leaf_node
          description: Daemon-wide route-map update delay in seconds; configure in the default VRF
          validators:
            integer-range:
              minimum: 0
              maximum: 600
          hints:
            0-600: Daemon-wide route-map update delay in seconds; configure in the default VRF
          default:
            value: '5'
            mode: direct

    suppress-fib-pending:
      kind: leaf_node
      description: Wait for kernel installation before advertising routes
      validators:
        list:
          values: enable disable
      choices:
        enable: Enable this behavior
        disable: Disable this behavior
      default:
        value: disable
        mode: direct

    suppress-fib-pending-delay:
      kind: leaf_node
      description: Delay before advertising kernel-installed routes in milliseconds
      validators:
        integer-range:
          minimum: 0
          maximum: 10000
      hints:
        0-10000: Delay before advertising kernel-installed routes in milliseconds

    max-med:
      kind: node
      description: Advertise a maximum MED during maintenance or startup
      anchor: true
      children:

        administrative:
          kind: leaf_node
          description: MED advertised during administrative maintenance
          validators:
            integer-range:
              minimum: 0
              maximum: 4294967295
          hints:
            0-4294967295: MED advertised during administrative maintenance

        on-startup:
          kind: node
          description: Temporary maximum MED after BGP starts
          anchor: true
          children:

            time:
              kind: leaf_node
              description: Startup maximum-MED duration in seconds
              validators:
                integer-range:
                  minimum: 5
                  maximum: 86400
              hints:
                5-86400: Startup maximum-MED duration in seconds

            med:
              kind: leaf_node
              description: MED advertised during startup
              validators:
                integer-range:
                  minimum: 0
                  maximum: 4294967295
              hints:
                0-4294967295: MED advertised during startup
              default:
                value: '4294967294'
                mode: direct

    tcp-keepalive:
      kind: node
      description: TCP keepalive probes for BGP sessions
      anchor: true
      children:

        idle:
          kind: leaf_node
          description: Idle seconds before TCP keepalive probes
          validators:
            integer-range:
              minimum: 1
              maximum: 65535
          hints:
            1-65535: Idle seconds before TCP keepalive probes

        interval:
          kind: leaf_node
          description: Seconds between TCP keepalive probes
          validators:
            integer-range:
              minimum: 1
              maximum: 65535
          hints:
            1-65535: Seconds between TCP keepalive probes

        probes:
          kind: leaf_node
          description: Unanswered TCP probes before disconnect
          validators:
            integer-range:
              minimum: 1
              maximum: 30
          hints:
            1-30: Unanswered TCP probes before disconnect

    dampening:
      kind: node
      description: Suppress repeatedly flapping IPv4 unicast routes
      anchor: true
      children:

        state:
          kind: leaf_node
          description: IPv4 unicast route-flap dampening
          validators:
            list:
              values: enable disable
          choices:
            enable: Suppress repeatedly flapping routes
            disable: Disable route-flap dampening
          default:
            value: disable
            mode: direct

        half-life:
          kind: leaf_node
          description: Penalty half-life in minutes
          validators:
            integer-range:
              minimum: 1
              maximum: 45
          hints:
            1-45: Penalty half-life in minutes
          default:
            value: '15'
            mode: direct

        reuse:
          kind: leaf_node
          description: Penalty below which a route becomes reusable
          validators:
            integer-range:
              minimum: 1
              maximum: 20000
          hints:
            1-20000: Penalty below which a route becomes reusable
          default:
            value: '750'
            mode: direct

        suppress:
          kind: leaf_node
          description: Penalty above which a route is suppressed
          validators:
            integer-range:
              minimum: 1
              maximum: 50000
          hints:
            1-50000: Penalty above which a route is suppressed
          default:
            value: '2000'
            mode: direct

        max-suppress-time:
          kind: leaf_node
          description: Maximum suppression time in minutes
          validators:
            integer-range:
              minimum: 1
              maximum: 255
          hints:
            1-255: Maximum suppression time in minutes
          default:
            value: '60'
            mode: direct
