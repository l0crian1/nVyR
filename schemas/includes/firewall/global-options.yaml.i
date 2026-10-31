global-options:
  kind: node
  anchor: true
  description: Settings shared by configured firewall chains
  children: # global-options

    include_schema:
    - file: firewall/kernel-options.yaml.i
      as: null
      replace:
        /connection-tracking/description: Connection tracking settings and application helpers
      add:
        /connection-tracking/children/helper:
          kind: node
          anchor: true
          description: Assign connection helpers on their standard service ports
          children:

            ftp:
              kind: leaf_node
              valueless: true
              description: File Transfer Protocol helper for TCP port 21

            tftp:
              kind: leaf_node
              valueless: true
              description: Trivial File Transfer Protocol helper for UDP port 69

            sip:
              kind: leaf_node
              valueless: true
              description: Session Initiation Protocol helper for TCP and UDP port 5060
    - file: firewall/reject-response.yaml.i
    - file: nftables/counter.yaml.i
      replace:
        /description: Count matching packets and bytes for every numbered firewall rule and map entry
    - file: nftables/last-used.yaml.i
      replace:
        /description: Record the last packet match time for every numbered firewall rule and map entry

    flowtable:
      kind: leaf_node
      description: Offload established forwarded TCP/UDP flows before the global accept policy
      depends: firewall-flowtable
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing flowtable; requires established state-policy action accept
      suggestors:
        config-path: {path: 'firewall flowtable'}

    state-policy:
      kind: node
      anchor: true
      description: Global connection-state policy
      children: # state-policy

        established:
          kind: node
          description: Established connections
          children: # established

            include_schema:
            - file: firewall/state-policy-action.yaml.i

        related:
          kind: node
          description: Related connections
          children: # related

            include_schema:
            - file: firewall/state-policy-action.yaml.i

        invalid:
          kind: node
          description: Invalid connection tracking state
          children: # invalid

            include_schema:
            - file: firewall/state-policy-action.yaml.i

    connection-accounting:
      kind: leaf_node
      valueless: true
      description: Enable per-connection accounting for packet and byte matches (new connections only)
