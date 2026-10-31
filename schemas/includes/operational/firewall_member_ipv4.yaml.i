# Reuse group entry validators, choices and hints for runtime key selection.
include_schema:
- file: firewall/group-entry_ipv4.yaml.i
  remove:
  - /description
  - /inbound-interface/depends
  - /outbound-interface/depends
  replace:
    /tcp-flags/description: Exact flags present in the learned key; names joined by and or a numeric byte
    /tcp-flags/joinable: true
    /tcp-flags/validators:
      mode: OR
      tcp-flags: {}
      integer-range: {minimum: 0, maximum: 255}
    /tcp-flags/hints:
      flag: Flags present in the exact key; join names with and
      0-255: Exact TCP flags byte (0 for no flags)
    /source-address/validators:
      ipv4-address: {}
    /source-address/hints:
      address: Exact learned address
    /destination-address/validators:
      ipv4-address: {}
    /destination-address/hints:
      address: Exact learned address
    /source-port/validators:
      integer-range: {minimum: 0, maximum: 65535}
    /source-port/hints:
      0-65535: Exact learned port
    /destination-port/validators:
      integer-range: {minimum: 0, maximum: 65535}
    /destination-port/hints:
      0-65535: Exact learned port
    /packet-mark/description: Exact learned packet-mark
    /packet-mark/validators:
      integer-range: {minimum: 0, maximum: 4294967295}
    /packet-mark/hints:
      0-4294967295: Exact learned value
    /dscp/description: Exact learned dscp
    /dscp/validators:
      integer-range: {minimum: 0, maximum: 63}
    /dscp/hints:
      0-63: Exact learned value
    /connection/children/mark/validators/integer-range/allow_range: false
    /connection/children/zone/validators/integer-range/allow_range: false
    /connection/children/id/validators/integer-range/allow_range: false
    /connection/children/original/children/zone/validators/integer-range/allow_range: false
    /connection/children/original/children/source-address/validators:
      ipv4-address: {}
    /connection/children/original/children/source-address/hints:
      address: Exact learned address
    /connection/children/original/children/source-port/validators:
      integer-range: {minimum: 0, maximum: 65535}
    /connection/children/original/children/source-port/hints:
      0-65535: Exact learned port
    /connection/children/original/children/destination-address/validators:
      ipv4-address: {}
    /connection/children/original/children/destination-address/hints:
      address: Exact learned address
    /connection/children/original/children/destination-port/validators:
      integer-range: {minimum: 0, maximum: 65535}
    /connection/children/original/children/destination-port/hints:
      0-65535: Exact learned port
    /connection/children/reply/children/zone/validators/integer-range/allow_range: false
    /connection/children/reply/children/source-address/validators:
      ipv4-address: {}
    /connection/children/reply/children/source-address/hints:
      address: Exact learned address
    /connection/children/reply/children/source-port/validators:
      integer-range: {minimum: 0, maximum: 65535}
    /connection/children/reply/children/source-port/hints:
      0-65535: Exact learned port
    /connection/children/reply/children/destination-address/validators:
      ipv4-address: {}
    /connection/children/reply/children/destination-address/hints:
      address: Exact learned address
    /connection/children/reply/children/destination-port/validators:
      integer-range: {minimum: 0, maximum: 65535}
    /connection/children/reply/children/destination-port/hints:
      0-65535: Exact learned port
