static:
  kind: node
  description: Static routes managed by FRR
  script:
    name: static
    priority: 40
    register:
      vrf: default
  children: # static

    include_schema:
    - file: protocols/route.yaml.i
    - file: protocols/route6.yaml.i
