login:
  kind: node
  description: Local users and access roles
  script:
    name: login
    priority: 1
  children: # login

    user:
      kind: tag_node
      strip_kind: private
      description: Local login account
      validators:
        regex: {pattern: '(?!(?:root|nvyr-dev)$)[a-z_][a-z0-9_-]{0,30}'}
      hints:
        username: Local account name (root and nvyr-dev are reserved)
      children: # user

        role:
          kind: leaf_node
          description: Account access role
          choices:
            dev-admin: Direct host access; requires installation developer access
            sys-admin: Router administration and ordinary account management
            net-admin: Router administration, including containers, images and reboot
            read-only: Inspection and diagnostics without configuration changes
          validators:
            list: {values: dev-admin sys-admin net-admin read-only}

        authentication:
          kind: node
          description: Local password authentication
          children: # authentication

            plaintext-password:
              kind: leaf_node
              strip_kind: password
              secret: true
              input_only: true
              description: Set a password (hashed immediately; never stored as plaintext)
              hints:
                password: 1–512 UTF-8 bytes; quote spaces

            encrypted-password:
              kind: leaf_node
              strip_kind: password
              secret: true
              description: Stored yescrypt password hash
              validators:
                regex: {pattern: '\$y\$j9T\$[./A-Za-z0-9]{22,86}\$[./A-Za-z0-9]{43}'}
              hints:
                hash: nVyR yescrypt hash; use plaintext-password to set a new password
