cpu:
  kind: node
  anchor: true
  description: CPU frequency and energy policy across all processors
  script:
    name: cpu
    priority: 2
  children:

    governor:
      kind: leaf_node
      description: Override the boot CPU governor (performance where supported)
      validators:
        cpu-policy: {setting: governor}
      suggestors:
        cpu-policy: {setting: governor}
      hints:
        governor: Available CPU frequency governor

    energy-performance:
      kind: leaf_node
      description: Hardware preference for performance versus energy savings
      validators:
        cpu-policy: {setting: energy-performance}
      suggestors:
        cpu-policy: {setting: energy-performance}
      hints:
        preference: Available hardware energy-performance preference
