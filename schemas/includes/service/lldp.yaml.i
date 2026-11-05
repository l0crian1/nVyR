lldp:
  kind: node
  anchor: true
  description: Link Layer Discovery Protocol
  script:
    name: lldp
    priority: 75
    watch:
    - interfaces
    - container
  children:

    disable:
      kind: leaf_node
      description: Stop the LLDP service
      valueless: true

    system-name:
      kind: leaf_node
      description: Advertised system name (native hostname when omitted)
      validators:
        mode: AND
        text: {}
        byte-length:
          minimum: 1
          maximum: 255
      hints:
        text: Advertised system name (native hostname when omitted)

    system-description:
      kind: leaf_node
      description: Advertised system description (native platform description when omitted)
      validators:
        mode: AND
        text: {}
        byte-length:
          minimum: 1
          maximum: 255
      hints:
        text: Advertised system description (native platform description when omitted)

    chassis-id:
      kind: leaf_node
      description: Custom local chassis identifier
      validators:
        mode: AND
        text: {}
        byte-length:
          minimum: 1
          maximum: 255
      hints:
        text: Custom local chassis identifier

    chassis-interface:
      kind: leaf_node
      description: Interfaces considered for native chassis identity
      multi: true
      suggestors:
        interfaces: {}
      validators:
        interface-match: {}
      hints:
        interface: Interface name or prefix followed by *

    management-address:
      kind: leaf_node
      description: Advertised management address
      multi: true
      strip_kind: ip
      validators:
        inet-address: {}
      hints:
        address: IPv4 or IPv6 management address

    management-interface:
      kind: leaf_node
      description: Select management addresses from matching interfaces
      multi: true
      suggestors:
        interfaces: {}
      validators:
        interface-match: {}
      hints:
        interface: Interface name or prefix followed by *

    capability:
      kind: leaf_node
      description: Override enabled capabilities supported by this host
      choices:
        bridge: Layer 2 bridge
        router: Layer 3 router
        station: End station
        wlan: Wireless access point
        telephone: Telephone
        repeater: Repeater
        docsis: DOCSIS cable device
        other: Other capability
      validators:
        list:
          values: bridge router station wlan telephone repeater docsis other
      multi: true

    disable-capability-advertisement:
      kind: leaf_node
      description: Omit the system capabilities TLV
      valueless: true

    disable-management-address-advertisement:
      kind: leaf_node
      description: Omit management address TLVs
      valueless: true

    mode:
      kind: leaf_node
      description: Default port mode (receive-transmit when omitted)
      choices:
        receive-transmit: Send and receive advertisements
        receive-only: Receive without sending
        transmit-only: Send without receiving
      validators:
        list:
          values: receive-transmit receive-only transmit-only

    transmit-interval:
      kind: leaf_node
      description: Seconds between advertisements (default 30)
      validators:
        integer-range:
          minimum: 1
          maximum: 3600
      hints:
        1-3600: Seconds between advertisements (default 30)

    hold-multiplier:
      kind: leaf_node
      description: Advertisement lifetime multiplier (default 4)
      validators:
        integer-range:
          minimum: 1
          maximum: 100
      hints:
        1-100: Advertisement lifetime multiplier (default 4)

    max-neighbors:
      kind: leaf_node
      description: Maximum neighbors per interface per protocol (default 32)
      validators:
        integer-range:
          minimum: 1
          maximum: 2147483647
      hints:
        1-2147483647: Maximum neighbors per interface per protocol (default 32)

    port-id:
      kind: leaf_node
      description: Global port identifier format (native automatic selection when omitted)
      choices:
        interface-name: Use the interface name
        mac-address: Use the interface MAC
      validators:
        list:
          values: interface-name mac-address

    port-description:
      kind: leaf_node
      description: Default advertised port description
      validators:
        mode: AND
        text: {}
        byte-length:
          minimum: 1
          maximum: 255
      hints:
        text: Default advertised port description

    agent-type:
      kind: leaf_node
      description: Propagation scope (default nearest-bridge)
      choices:
        nearest-bridge: Nearest bridge (01:80:c2:00:00:0e)
        nearest-non-tpmr-bridge: Nearest non-TPMR bridge (01:80:c2:00:00:03)
        nearest-customer-bridge: Nearest customer bridge (01:80:c2:00:00:00)
      validators:
        list:
          values: nearest-bridge nearest-non-tpmr-bridge nearest-customer-bridge

    bond-member-source-mac:
      kind: leaf_node
      description: Source MAC on bond members (default local)
      choices:
        local: Member MAC with locally administered bit and native fixed fallback
        real: Real member MAC
        zero: All-zero MAC
        fixed: Native fixed MAC 00:60:08:69:97:ef
      validators:
        list:
          values: local real zero fixed

    interface:
      kind: tag_node
      description: Select interfaces; only exact names accept overrides
      suggestors:
        interfaces: {}
      validators:
        interface-match: {}
      hints:
        interface: Interface name or prefix followed by *
      anchor: true
      choices:
        all: All interfaces eligible for native LLDP discovery
      children:

        disable:
          kind: leaf_node
          description: Disable sending and receiving on this port
          valueless: true

        mode:
          kind: leaf_node
          description: Override the global mode on this port
          choices:
            receive-transmit: Send and receive advertisements
            receive-only: Receive without sending
            transmit-only: Send without receiving
          validators:
            list:
              values: receive-transmit receive-only transmit-only

        port-id:
          kind: leaf_node
          description: Custom locally assigned port identifier
          validators:
            mode: AND
            text: {}
            byte-length:
              minimum: 1
              maximum: 255
          hints:
            text: Custom locally assigned port identifier

        port-description:
          kind: leaf_node
          description: Advertised description for this port
          validators:
            mode: AND
            text: {}
            byte-length:
              minimum: 1
              maximum: 255
          hints:
            text: Advertised description for this port

        transmit-vlan:
          kind: tag_node
          anchor: true
          description: Send tagged LLDP on one VLAN (0 means priority tagged)
          validators:
            integer-range:
              minimum: 0
              maximum: 4094
          hints:
            0-4094: 802.1Q VLAN identifier
          children:

            priority:
              kind: leaf_node
              description: 802.1p priority (default 0)
              validators:
                integer-range:
                  minimum: 0
                  maximum: 7
              hints:
                0-7: 802.1p priority (default 0)

            dei:
              kind: leaf_node
              description: Set the drop eligible indicator
              valueless: true

    exclude-interface:
      kind: leaf_node
      description: Exclude matching interfaces from LLDP participation
      multi: true
      suggestors:
        interfaces: {}
      validators:
        interface-match: {}
      hints:
        interface: Interface name or prefix followed by *
