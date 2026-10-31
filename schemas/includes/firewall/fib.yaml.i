fib:
  kind: node
  description: Match a routing-table lookup using packet fields
  children: # fib

    lookup:
      kind: node
      anchor: true
      description: Packet fields used for the FIB lookup
      children: # lookup

        source-address:
          kind: leaf_node
          description: Look up the packet source address
          valueless: true

        destination-address:
          kind: leaf_node
          description: Look up the packet destination address
          valueless: true

        inbound-interface:
          kind: leaf_node
          description: Include the incoming interface in the lookup
          valueless: true

        outbound-interface:
          kind: leaf_node
          description: Include the outgoing interface (route-type results only)
          valueless: true

        packet-mark:
          kind: leaf_node
          description: Include the packet mark in the lookup
          valueless: true

    result:
      kind: node
      description: Expected FIB lookup result
      children: # result

        outbound-interface:
          kind: leaf_node
          negatable: true
          description: Match outgoing interface names or route existence
          multi: true
          choices:
            exists: A route was found
            missing: No route was found
          validators:
            regex: {pattern: '[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}'}
          hints:
            interface: Outgoing interface name
          suggestors:
            interfaces: {}

        route-type:
          kind: leaf_node
          negatable: true
          description: Match the address type returned by the lookup
          multi: true
          choices:
            unspec: Unspecified address type
            unicast: Unicast address
            local: Address on this router
            broadcast: Broadcast address
            anycast: Anycast address
            multicast: Multicast address
            blackhole: Silently discarded destination
            unreachable: Unreachable destination
            prohibit: Administratively prohibited destination
          validators:
            list: {values: unspec unicast local broadcast anycast multicast blackhole unreachable prohibit}
