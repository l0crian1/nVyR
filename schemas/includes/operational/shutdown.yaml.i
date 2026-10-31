children: # shutdown

  reboot:
    access: net-admin
    kind: node
    description: Reboot the router after the default one-minute delay
    command: ['shutdown.nvyr.op', 'reboot']
    stream: true
    children: # reboot

      now:
        kind: node
        description: Reboot immediately after confirmation
        command: ['shutdown.nvyr.op', 'reboot', 'now']
        stream: true

      in:
        kind: leaf_node
        description: Reboot after a delay in minutes
        command: ['shutdown.nvyr.op', 'reboot', '@3']
        stream: true
        validators:
          positive-integer: {}
        hints:
          minutes: Whole minutes from now

      at:
        kind: leaf_node
        description: Reboot at a 24-hour time
        command: ['shutdown.nvyr.op', 'reboot', '@3']
        stream: true
        validators:
          regex: {pattern: '(?:[01]?[0-9]|2[0-3]):[0-5][0-9]'}
        hints:
          'HH:MM': Hours and minutes, such as 14:30 or 6:05

      cancel:
        kind: node
        description: Cancel a scheduled reboot
        command: ['shutdown.nvyr.op', 'cancel']

  poweroff:
    access: net-admin
    kind: node
    description: Power off the router after the default one-minute delay
    command: ['shutdown.nvyr.op', 'poweroff']
    stream: true
    children: # poweroff

      now:
        kind: node
        description: Power off immediately after confirmation
        command: ['shutdown.nvyr.op', 'poweroff', 'now']
        stream: true

      in:
        kind: leaf_node
        description: Power off after a delay in minutes
        command: ['shutdown.nvyr.op', 'poweroff', '@3']
        stream: true
        validators:
          positive-integer: {}
        hints:
          minutes: Whole minutes from now

      at:
        kind: leaf_node
        description: Power off at a 24-hour time
        command: ['shutdown.nvyr.op', 'poweroff', '@3']
        stream: true
        validators:
          regex: {pattern: '(?:[01]?[0-9]|2[0-3]):[0-5][0-9]'}
        hints:
          'HH:MM': Hours and minutes, such as 14:30 or 6:05

      cancel:
        kind: node
        description: Cancel a scheduled poweroff
        command: ['shutdown.nvyr.op', 'cancel']
