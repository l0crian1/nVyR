dhcpv6-pd:
  kind: tag_node
  anchor: true
  description: Request a delegated IPv6 prefix using this IAID
  validators:
    integer-range: {minimum: 0, maximum: 4294967295}
    regex: {pattern: '0|[1-9][0-9]*'}
  hints:
    iaid: Decimal delegation request ID
  children:

    length:
      kind: leaf_node
      description: Preferred delegated prefix length sent to the ISP
      validators:
        integer-range: {minimum: 1, maximum: 64}
      hints:
        1-64: Requested prefix length

    interface:
      kind: tag_node
      anchor: true
      description: Assign and advertise a delegated /64 on this LAN
      depends: interface
      validators:
        regex: {pattern: '[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
      suggestors:
        interfaces: {}
      hints:
        interface: Configured downstream interface or VIF
      children:

        subnet-id:
          kind: leaf_node
          description: Decimal index of the LAN /64 within the delegation
          validators:
            integer-range: {minimum: 0, maximum: 18446744073709551615}
          hints:
            number: Zero-based subnet number

        address:
          kind: leaf_node
          description: Decimal host number assigned to the router inside the /64
          validators:
            integer-range: {minimum: 1, maximum: 18446744073709551615}
          hints:
            number: Router host number, for example 254 for ::fe
          default:
            mode: direct
            value: '1'
