ipv4:
  kind: node
  description: IPv4 firewall settings
  children: # ipv4

    include_schema:
    - file: firewall/source-validation.yaml.i
    - file: firewall/ingress.yaml.i
    - file: firewall/name_ipv4.yaml.i

    input:
      kind: node
      description: Traffic destined for this router
      children: # input

        include_schema:
        - file: firewall/filter.yaml.i
          remove:
          - /children/rule/children/modify/children/tcp-mss/choices
          replace:
            /children/rule/children/modify/children/tcp-mss/validators:
              integer-range: {minimum: 1, maximum: 65535}

    forward:
      kind: node
      description: Traffic forwarded through the router
      children: # forward

        include_schema:
        - file: firewall/filter.yaml.i
          replace:
            /children/rule/children/action/validators/list/values: accept drop reject jump continue return offload
          add:
            /children/rule/children/action/choices/offload: Offload matching flows to a configured flowtable
            /children/rule/children/offload-target:
              include_schema:
              - file: firewall/offload-target.yaml.i
                as: null

    output:
      kind: node
      description: Traffic originating from this router
      children: # output

        include_schema:
        - file: firewall/filter.yaml.i
        - file: firewall/output_raw.yaml.i

    prerouting:
      kind: node
      description: Incoming IPv4 traffic before routing
      children: # prerouting

        include_schema:
        - file: firewall/raw.yaml.i
