#!/usr/bin/env python3
"""Reboot and poweroff through shutdown, without its cancel-command hint."""

from nvyr import opmode
from nvyr.helpers.process import cmd, rc_cmd


def _visible(text):
    """Keep the scheduled-action text and drop the trailing shutdown -c hint."""
    lines = [line.split(',', 1)[0].rstrip() for line in text.splitlines()]
    lines = [line for line in lines if line]

    return '\n'.join(lines) + '\n' if lines else ''


def _schedule(action, flag, when):
    timing = ('in one minute' if when is None else
              'now' if when == 'now' else
              f'at {when}' if ':' in when else f'in {when} minutes')
    if input(f'{action} the router {timing}? [y/N] ').strip().lower() not in {'y', 'yes'}:
        return 'Command cancelled.\n'

    arguments = ['shutdown', flag]
    if when is not None:
        arguments.append(when)

    return _visible(cmd(arguments))


@opmode.command
def reboot(when: str | None = None, /):
    """Confirm a reboot, using shutdown's default delay when no time is supplied."""
    return _schedule('Reboot', '-r', when)


@opmode.command
def poweroff(when: str | None = None, /):
    """Confirm a poweroff, using shutdown's default delay when no time is supplied."""
    return _schedule('Power off', '-P', when)


@opmode.command
def cancel():
    """Cancel a scheduled reboot or poweroff."""
    return cmd(['shutdown', '-c'])


@opmode.command
def show():
    """Show the scheduled reboot or poweroff."""
    # "No scheduled shutdown" is a normal display result despite its nonzero exit.
    _, output = rc_cmd(['shutdown', '--show'])
    return output


if __name__ == '__main__':
    opmode.run()
