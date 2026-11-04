task:
  kind: tag_node
  description: Scheduled local commands
  validators:
    regex: {pattern: '[A-Za-z0-9][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Unique task name
  script:
    name: task
    priority: 99
  children:

    exec:
      kind: leaf_node
      description: Run a host shell command as root (sys-admin or dev-admin)
      validators:
        regex: {pattern: '.*\S.*'}
      hints:
        command: Single quoted shell command or script path

    op-command:
      kind: leaf_node
      description: Run an unattended operational command
      validators:
        task-op-command: {}
      suggestors:
        task-op-commands: {}
      hints:
        operational-command: Quoted operational command, for example 'show interfaces'

    disable:
      kind: leaf_node
      valueless: true
      description: Pause scheduling and manual starts for this task

    interval:
      kind: leaf_node
      description: Time between one execution finishing and the next starting
      validators:
        duration: {maximum: 31536000}
      hints:
        duration: Positive interval in seconds, minutes, hours or days (for example 6h)

    calendar:
      kind: node
      description: Run at local clock times on matching days
      children:

        at:
          kind: leaf_node
          multi: true
          description: Local clock time in 24-hour notation
          validators:
            regex: {pattern: '(?:[01][0-9]|2[0-3]):[0-5][0-9]'}
          hints:
            HH:MM: Local hour and minute, for example 06:30

        day-of-week:
          kind: leaf_node
          multi: true
          description: Days of the week on which this task may run
          choices:
            monday: Monday
            tuesday: Tuesday
            wednesday: Wednesday
            thursday: Thursday
            friday: Friday
            saturday: Saturday
            sunday: Sunday
            weekdays: Monday through Friday
            weekends: Saturday and Sunday
          validators:
            list: {values: monday tuesday wednesday thursday friday saturday sunday weekdays weekends}

        day-of-month:
          kind: leaf_node
          multi: true
          description: Days of the month on which this task may run
          choices:
            last: Last calendar day of each month
          hints:
            1-31: Calendar day number
          validators:
            regex: {pattern: '(?:[1-9]|[12][0-9]|3[01]|last)'}
