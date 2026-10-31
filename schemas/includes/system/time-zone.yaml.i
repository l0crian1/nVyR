time-zone:
  kind: leaf_node
  description: Local time zone
  hints:
    area/location: Installed IANA time zone, such as America/New_York or UTC
  validators:
    time-zone: {}
  suggestors:
    time-zones: {}
  default:
    mode: always
    value: UTC
  script:
    name: time-zone
    priority: 0
