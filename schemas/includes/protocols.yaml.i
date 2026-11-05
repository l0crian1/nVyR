protocols:
  kind: node
  description: Routing protocols
  children: # protocols

    include_schema:
    - file: protocols/static.yaml.i
    - file: protocols/bgp.yaml.i
    - file: protocols/ospf.yaml.i
    - file: protocols/ospfv3.yaml.i
    - file: protocols/rip.yaml.i
    - file: protocols/ripng.yaml.i
