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

    include_schema:
    - file: system/schedule.yaml.i
      as: null

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
