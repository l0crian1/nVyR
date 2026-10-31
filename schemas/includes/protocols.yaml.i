protocols:
  kind: node
  description: Routing protocols
  children: # protocols

    include_schema:
    - file: protocols/static.yaml.i
    - file: protocols/bgp.yaml.i
