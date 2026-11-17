children:

  include_schema:
  - file: operational/bgp-table.yaml.i
    as: null

  rd:
    kind: tag_node
    description: Routes from one route distinguisher
    validators:
      mode: OR
      bgp-rd-rt: {}
      list:
        values: all
    choices:
      all: All route distinguishers
    hints:
      rd: ASN:number or IPv4:number
    command: ["bgp.nvyr.op", "show", "@line"]
    children:

      prefix:
        kind: tag_node
        description: VPN destination prefix
        positional: true
        validators:
          mode: OR
          ipv4-prefix: {}
          ipv6-prefix: {}
        hints:
          prefix: IPv4 or IPv6 prefix
        command: ["bgp.nvyr.op", "show", "@line"]
