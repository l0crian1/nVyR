fail-safe:
  kind: node
  description: Early firewall protection until the main firewall is installed
  script:
    name: firewall_failsafe
    priority: 2
  children:

    # The builder strips registrar metadata and scopes suggestions after expansion.
    include_schema:
    - file: firewall/description.yaml.i
    - file: firewall/global-options.yaml.i
      remove:
      - /children/flowtable
      - /children/ipv4
      - /children/ipv6
      - /children/syn-cookies
      - /children/connection-tracking
      - /children/flowtable-timeout
    - file: firewall/zone.yaml.i
    - file: firewall/zone-policy.yaml.i
    - file: firewall/group.yaml.i
      remove:
      - /children/domain-group
      - /children/address-group/children/ipv4/children/geoip
      - /children/address-group/children/ipv6/children/geoip
    - file: firewall/ipv4.yaml.i
      remove:
      - /children/ingress
      - /children/forward/children/filter/children/rule/children/offload-target
      - /children/forward/children/filter/children/rule/children/action/choices/offload
      replace:
        /children/forward/children/filter/children/rule/children/action/validators/list/values: accept drop reject jump continue return
    - file: firewall/ipv6.yaml.i
      remove:
      - /children/ingress
      - /children/forward/children/filter/children/rule/children/offload-target
      - /children/forward/children/filter/children/rule/children/action/choices/offload
      replace:
        /children/forward/children/filter/children/rule/children/action/validators/list/values: accept drop reject jump continue return
    - file: firewall/inet.yaml.i
      remove:
      - /children/ingress
      - /children/forward/children/filter/children/rule/children/offload-target
      - /children/forward/children/filter/children/rule/children/action/choices/offload
      replace:
        /children/forward/children/filter/children/rule/children/action/validators/list/values: accept drop reject jump continue return
