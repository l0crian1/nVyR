ha:
  kind: node
  anchor: true
  description: Synchronize leases and fail over between Kea servers
  children:

    mode:
      kind: leaf_node
      description: Share client requests or keep a standby server
      choices:
        active-active: Primary and secondary both serve clients
        active-passive: Primary serves clients while standby waits
      validators:
        list: {values: active-active active-passive}
      default:
        mode: direct
        value: active-active

    name:
      kind: leaf_node
      description: Local member name shared with the other HA members
      hints:
        name: Unique local member name; for example ROUTER1
      validators:
        regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'}

    source-address:
      kind: leaf_node
      description: Local address for the HA peer listener in this routing instance
      hints:
        address: Local IPv4 or IPv6 address reachable by the other members
      validators:
        dhcp-ha-address: {}

    port:
      kind: leaf_node
      description: Local TCP port for HA communication
      hints:
        1-65535: HA listener port
      validators:
        integer-range: {minimum: 1, maximum: 65535}
      default:
        mode: direct
        value: '8005'

    role:
      kind: leaf_node
      description: Local member's role in the HA relationship
      choices:
        primary: Active server in either mode
        secondary: Second active server in active-active mode
        standby: Failover server in active-passive mode
        backup: Additional lease replica without automatic takeover
      validators:
        list: {values: primary secondary standby backup}

    peer:
      kind: tag_node
      anchor: true
      description: Remote member of this HA relationship
      hints:
        name: Unique remote member name matching its local HA name
      validators:
        regex: {pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'}
      children:

        address:
          kind: leaf_node
          description: Address used to reach this remote HA member
          hints:
            address: Remote IPv4 or IPv6 HA listener address
          validators:
            dhcp-ha-address: {}

        port:
          kind: leaf_node
          description: Remote TCP port for HA communication
          hints:
            1-65535: Peer HA listener port
          validators:
            integer-range: {minimum: 1, maximum: 65535}
          default:
            mode: direct
            value: '8005'

        role:
          kind: leaf_node
          description: Role configured on this remote HA member
          choices:
            primary: Active server in either mode
            secondary: Second active server in active-active mode
            standby: Failover server in active-passive mode
            backup: Additional lease replica without automatic takeover
          validators:
            list: {values: primary secondary standby backup}
