geoip:
  kind: node
  anchor: true
  description: Maintain country address ranges from DB-IP Country Lite
  children:

    country:
      kind: leaf_node
      multi: true
      description: Country to include in this group
      validators:
        geoip-country: {}
      suggestors:
        geoip-countries: {}
      hints:
        country: Uppercase country code (US, CA, GB); XK is Kosovo, ZZ is unlocated/reserved
