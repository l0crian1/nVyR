# Inet rules execute in base chains and fall through to family dispatch.
include_schema:
- file: firewall/ipv4.yaml.i
  as: inet

  remove:
  - /children/input/children/filter/children/default-action
  - /children/input/children/filter/children/default-log
  - /children/forward/children/filter/children/default-action
  - /children/forward/children/filter/children/default-log
  - /children/output/children/filter/children/default-action
  - /children/output/children/filter/children/default-log
  - /children/output/children/raw/children/default-action
  - /children/output/children/raw/children/default-log
  - /children/prerouting/children/raw/children/default-action
  - /children/prerouting/children/raw/children/default-log
  - /children/ingress/children/filter/children/default-action
  - /children/ingress/children/filter/children/default-log

  replace:
    /description: Family-neutral firewall rules before IPv4 and IPv6 dispatch
    /children/name/dependency: firewall-chain-inet
    /children/prerouting/description: Incoming traffic before routing
    /children/name/description: Named family-neutral firewall chain

    /children/input/children/filter/children/rule:
      include_schema:
      - file: firewall/rule_inet.yaml.i
        as: null
        remove:
        - /children/modify/children/tcp-mss/choices
        replace:
          /children/modify/children/tcp-mss/validators:
            integer-range: {minimum: 1, maximum: 65535}

    /children/forward/children/filter/children/rule:
      include_schema:
      - file: firewall/rule_inet.yaml.i
        as: null

        replace:
          /children/action/validators/list/values: accept drop reject jump continue return offload
        add:
          /children/action/choices/offload: Offload matching flows to a configured flowtable
          /children/offload-target:
            include_schema:
            - file: firewall/offload-target.yaml.i
              as: null

    /children/output/children/filter/children/rule:
      include_schema:
      - file: firewall/rule_inet.yaml.i
        as: null

    /children/output/children/raw/children/rule:
      include_schema:
      - file: firewall/rule_inet.yaml.i
        as: null

        remove:
        - /children/connection/children/timeout-group
        - /children/modify/children/connection-mark
        - /children/inbound-interface
        - /children/inbound-interface-group
        - /children/inbound-link-group
        add:
          /children/notrack:
            kind: leaf_node
            valueless: true
            description: Exclude matching packets from connection tracking

    /children/prerouting/children/raw/children/rule:
      include_schema:
      - file: firewall/rule_inet.yaml.i
        as: null

        remove:
        - /children/connection/children/timeout-group
        - /children/modify/children/connection-mark
        - /children/outbound-interface
        - /children/outbound-interface-group
        - /children/outbound-link-group
        - /children/modify/children/tcp-mss/choices
        replace:
          /children/modify/children/tcp-mss/validators:
            integer-range: {minimum: 1, maximum: 65535}
        add:
          /children/notrack:
            kind: leaf_node
            valueless: true
            description: Exclude matching packets from connection tracking

    /children/ingress/children/filter/children/rule:
      include_schema:
      - file: firewall/rule_inet.yaml.i
        as: null

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
          /children/limit/children/per/validators/list/values: source-port destination-port protocol inbound-interface inbound-link-group
            source-mac destination-mac packet-mark
        add:
          /children/vlan:
            include_schema:
            - file: firewall/vlan.yaml.i
              as: null
          /children/notrack:
            kind: leaf_node
            valueless: true
            description: Exclude matching packets from connection tracking

    /children/name/children/rule:
      include_schema:
      - file: firewall/rule_inet.yaml.i
        as: null
        add:
          /children/vlan:
            include_schema:
            - file: firewall/vlan.yaml.i
              as: null
