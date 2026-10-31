# Power management

For implementation and testing, see the [developer guide](../dev/power-management.md).

Reboot, power off, or inspect a scheduled shutdown from operational mode.
From configuration mode, prefix these commands with `run`.

## Reboot and poweroff

Net-admins and administrators can reboot or power off the router from operational mode:

```text
reboot
reboot now
reboot in 15
reboot at 14:30
reboot cancel

poweroff
poweroff now
poweroff in 15
poweroff at 06:05
poweroff cancel

show reboot
show poweroff
```

Reboot and poweroff actions ask for confirmation through the existing interactive
terminal runner. Enter or a negative answer cancels; `y` or `yes` proceeds.
Ctrl+C or EOF also cancels without scheduling an action. Cancel and show commands
do not ask for confirmation.

Bare `reboot` and `poweroff` pass no time argument, preserving
[shutdown's default one-minute delay](https://www.freedesktop.org/software/systemd/man/latest/shutdown.html).
Immediate actions require `reboot now` or `poweroff now` and still ask for confirmation.
Minutes must be a whole number greater than
zero. Times use 24-hour `HH:MM`, with one or two hour digits and two minute digits.
Read-only accounts cannot see or run the
action commands, including through `run`. The show commands are available to every
role.
