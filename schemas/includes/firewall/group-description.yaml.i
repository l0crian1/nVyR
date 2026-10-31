include_schema:
- file: generic/description.yaml.i
  replace:
    /description: Group description (at most 128 UTF-8 bytes)
    /hints:
      text: Group description; quote spaces, no embedded double quotes
  add:
    /validators:
      mode: AND
      text: {}
      byte-length: {maximum: 128}
      regex: {pattern: '[^"]*'}
