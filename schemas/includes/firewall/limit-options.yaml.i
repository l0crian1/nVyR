children: # limit options

  include_schema:
  - file: firewall/limit-per.yaml.i
  - file: firewall/limit-prefixes.yaml.i
    as: null

  rate:
    kind: node
    description: Packet or byte rate per second, minute, hour or day
    children: # rate

      packets:
        kind: leaf_node
        description: Packet rate
        validators:
          limit-rate: {unit: packets}
        hints:
          rate: Whole packets per s, m, h or d; for example 10/s or 60/m

      bytes:
        kind: leaf_node
        description: Byte rate (k, m and g use multiples of 1024)
        validators:
          limit-rate: {unit: bytes}
        hints:
          rate: Whole bytes with optional k, m or g suffix per s, m, h or d; for example 1g/s

  burst:
    kind: node
    description: Packet bucket capacity or additional byte allowance (native defaults when omitted)
    children: # burst

      packets:
        kind: leaf_node
        description: Packet bucket capacity (native default 5)
        validators:
          limit-burst: {unit: packets}
        hints:
          packets: Positive whole packet count

      bytes:
        kind: leaf_node
        description: Additional byte allowance (native default 0)
        validators:
          limit-burst: {unit: bytes}
        hints:
          bytes: Whole bytes with optional k, m or g suffix; for example 64k

  over:
    kind: leaf_node
    valueless: true
    description: Match traffic exceeding the allowance instead of traffic within it

  size:
    kind: leaf_node
    description: Maximum per-key allowances (default 65536; requires per)
    validators:
      integer-range: {minimum: 1, maximum: 4294967295}
    hints:
      1-4294967295: Maximum number of tracked keys

  timeout:
    kind: leaf_node
    description: Idle lifetime of a per-key allowance; must cover its full refill time
    validators:
      duration: {maximum: 18446744073}
    hints:
      duration: Time in s, m, h or d; default at least 1m and one full refill
