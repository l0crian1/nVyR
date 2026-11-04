# Task scheduling

Systemd owns execution. The configuration script validates the relationship between action and schedule in `verify()`, builds units in `generate()`, and reconciles them in `apply()`. No scheduler loop runs inside configd.

To add a schedule under another feature:

1. Keep the schedule in that feature's schema. In `generate()`, use `task_schedule.render(owner, name, kind, argv, schedule)` with a stable lowercase alphanumeric owner and a literal argv list. Schedule accepts the same interval or calendar dictionary as a user task.
2. Collect all filename/text pairs belonging to the owner. In `apply()`, call `task_schedule.reconcile(owner, files, recover=context.recovery)` once. An empty set of files removes that owner's previous units. Use a distinct owner for each independently committed feature.
3. Use `op` for a fixed operation and `exec` for an administrator's shell action. The unit name includes owner, action type, and task name. This isolates operations, privileges, and logs even if two owners choose the same task name. `show system tasks` discovers them together.

User-entered operational actions resolve through the installed schema at validation and generation. They use argv substitution, never shell expansion. A streamed operational action can opt in with `unattended: true` on its command node after verifying that it needs neither an interactive terminal nor a prompt. Captured displays retain their timeout. Administrative commands outside the scheduler's supported operational access level are rejected.

Timers and services live under `/run/systemd/system`. Boot recovery recreates them from the saved configuration; live commits replace changed files and leave unrelated timers armed. A failed installation restores the previous files and timers. Task output goes to `/var/log/nvyr/tasks`.

See [Scheduled tasks](../users/tasks.md) for examples.
