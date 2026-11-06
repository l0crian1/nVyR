from-csv:
  kind: tag_node
  description: External membership source
  validators:
    regex:
      pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'
  hints:
    name: Attachment name, used in element comments
  children:

    include_schema:
    - file: system/schedule.yaml.i
      as: null

    source:
      kind: leaf_node
      description: Local file or HTTP(S), FTP(S), or TFTP URL
      validators:
        firewall-list-source: {}
      hints:
        path-or-url: Absolute local filename or supported URL
