children: # translation

  port:
    kind: leaf_node
    description: Translation port or inclusive port range
    validators:
      port: {allow_range: true}
    hints:
      1-65535: Translation port
      start-end: Inclusive ascending translation port range

  port-mapping:
    kind: leaf_node
    description: Transport port selection behavior
    choices:
      default: Use the kernel's default port selection
      random: Randomize port selection
      fully-random: Fully randomize port selection
    validators:
      list: {values: default random fully-random}

  persistent:
    kind: leaf_node
    description: Keep translated address selection stable for a client across connections
    valueless: true
