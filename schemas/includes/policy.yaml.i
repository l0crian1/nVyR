policy:
  kind: "node"
  description: "Reusable routing policies"
  script:
    name: "policy"
    priority: 35
  children:

    include_schema:
    - file: policy/access-list.yaml.i
    - file: policy/prefix-list.yaml.i
    - file: policy/as-path-list.yaml.i
    - file: policy/community-list.yaml.i
    - file: policy/large-community-list.yaml.i
    - file: policy/route-map.yaml.i
