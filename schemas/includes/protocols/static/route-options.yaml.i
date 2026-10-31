children: # static route (shared)

  include_schema:
  - file: generic/description.yaml.i
    replace:
      /description: Static route description
      /hints:
        text: Description; quote spaces
    add:
      /validators:
        text: {}
  - file: generic/disable.yaml.i
    replace:
      /description: Disable this route and all its next hops
  - file: protocols/static/interface.yaml.i
  - file: protocols/static/discard.yaml.i
    as: null
