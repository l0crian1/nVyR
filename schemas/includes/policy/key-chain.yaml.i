key-chain:
  kind: tag_node
  description: Reusable routing authentication keychain
  anchor: true
  validators:
    regex:
      pattern: '[A-Za-z_][A-Za-z0-9_.-]{0,127}'
  hints:
    name: Reusable routing authentication keychain
  children:

    key:
      kind: tag_node
      description: Authentication key ID
      anchor: true
      validators:
        integer-range:
          minimum: 0
          maximum: 2147483647
      hints:
        key-id: Authentication key ID
      children:

        secret:
          kind: leaf_node
          description: Authentication secret (hidden by strip-private)
          validators:
            regex:
              pattern: '[^\s"\\]{1,128}'
          hints:
            secret: Authentication secret (hidden by strip-private)
          secret: true

        algorithm:
          kind: leaf_node
          description: Key authentication algorithm
          validators:
            list:
              values: md5 hmac-sha-1 hmac-sha-256 hmac-sha-384 hmac-sha-512
          choices:
            md5: MD5 authentication
            hmac-sha-1: HMAC-SHA-1 authentication
            hmac-sha-256: HMAC-SHA-256 authentication
            hmac-sha-384: HMAC-SHA-384 authentication
            hmac-sha-512: HMAC-SHA-512 authentication

        accept-lifetime:
          kind: node
          description: Authentication key validity in the router time zone
          anchor: true
          children:

            start:
              kind: leaf_node
              description: Start time in the router time zone
              validators:
                routing-key-time: {}
              hints:
                YYYY-MM-DDTHH:MM:SS: Start time in the router time zone

            end:
              kind: leaf_node
              description: End time in the router time zone
              validators:
                routing-key-time: {}
              hints:
                YYYY-MM-DDTHH:MM:SS: End time in the router time zone

            duration:
              kind: leaf_node
              description: Validity after start in seconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 2147483646
              hints:
                1-2147483646: Validity after start in seconds

            infinite:
              kind: leaf_node
              description: No expiry after the start time
              valueless: true

        send-lifetime:
          kind: node
          description: Authentication key validity in the router time zone
          anchor: true
          children:

            start:
              kind: leaf_node
              description: Start time in the router time zone
              validators:
                routing-key-time: {}
              hints:
                YYYY-MM-DDTHH:MM:SS: Start time in the router time zone

            end:
              kind: leaf_node
              description: End time in the router time zone
              validators:
                routing-key-time: {}
              hints:
                YYYY-MM-DDTHH:MM:SS: End time in the router time zone

            duration:
              kind: leaf_node
              description: Validity after start in seconds
              validators:
                integer-range:
                  minimum: 1
                  maximum: 2147483646
              hints:
                1-2147483646: Validity after start in seconds

            infinite:
              kind: leaf_node
              description: No expiry after the start time
              valueless: true
  dependency: policy-key-chain
