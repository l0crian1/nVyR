ingress:
  kind: node
  description: Filter incoming IP packets before routing and connection tracking
  children:

    filter:
      kind: node
      anchor: true
      description: Ingress packet filtering before flow offload
      children:

        interface:
          kind: leaf_node
          multi: true
          description: Ingress interface name or trailing prefix wildcard
          validators:
            interface-match: {}
          hints:
            name: Interface name or prefix* (matching interfaces may be created later)
          suggestors:
            interfaces: {}

        include_schema:
        - file: firewall/defaults.yaml.i
          as: null
        - file: firewall/rule.yaml.i
          remove:
          - /children/modify
          - /children/connection
          - /children/fib
          - /children/outbound-interface
          - /children/outbound-interface-group
          - /children/outbound-link-group
          - /children/limit/children/per/choices/outbound-interface
          - /children/limit/children/per/choices/outbound-link-group
          - /children/limit/children/per/choices/connection-mark
          replace:
            /children/limit/children/per/validators/list/values: source-address destination-address source-port destination-port protocol inbound-interface inbound-link-group source-mac destination-mac packet-mark
          add:
            /children/notrack:
              kind: leaf_node
              valueless: true
              description: Disable connection tracking for matching packets

            /children/vlan:
              include_schema:
              - file: firewall/vlan.yaml.i
                as: null
