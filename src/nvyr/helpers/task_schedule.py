"""Render and reconcile systemd schedules owned by one configuration script."""

from pathlib import Path
import re

from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers import template
from nvyr.helpers.process import cmd

UNITS = Path('/run/systemd/system')
LOGS = Path('/var/log/nvyr/tasks')
DAYS = ('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday')


def calendar_expressions(calendar):
    days = set(calendar.get('day-of-week', ()))
    if 'weekdays' in days:
        days.update(DAYS[:5])
    if 'weekends' in days:
        days.update(DAYS[5:])
    weekdays = ','.join(day[:3].title() for day in DAYS if day in days)

    month = set(calendar.get('day-of-month', ()))
    numbers = sorted(int(day) for day in month if day != 'last')
    dates = ['*-*-' + ','.join(map(str, numbers))] if numbers else []
    if 'last' in month:
        dates.append('*-*~01')
    return [' '.join(filter(None, (weekdays, date, at))) for date in dates or ['*-*-*']
            for at in sorted(calendar['at'])]


def unit(owner, kind, name):
    # Separate privilege classes cannot reuse one another's services or logs.
    if (not re.fullmatch('[a-z0-9]+', owner) or kind not in ('exec', 'op')
            or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,62}', name)):
        raise ValueError('Invalid scheduled task identity')
    return f'nvyr-task-{owner}-{kind}-{name}'


def render(owner, name, kind, argv, schedule):
    """Return unit filename/text pairs; merge tasks from one owner before applying."""
    stem = unit(owner, kind, name)
    # The ':' ExecStart prefix disables environment substitution. Escape systemd specifiers separately.
    command = ' '.join('"' + arg.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"' for arg in argv)
    variables = {'owner': owner, 'name': name, 'command': command, 'log': LOGS / (stem + '.log')}
    files = {stem + '.service': template.render('tasks/task.service.j2', variables)}
    if 'disable' not in schedule:
        variables['interval'] = schedule.get('interval')
        variables['calendar'] = calendar_expressions(schedule['calendar']) if 'calendar' in schedule else []
        files[stem + '.timer'] = template.render('tasks/task.timer.j2', variables)
    return files


def installed(owner):
    if not re.fullmatch('[a-z0-9]+', owner):
        raise ValueError('Invalid scheduler owner')
    return {p.name: p.read_text() for p in UNITS.glob(f'nvyr-task-{owner}-*') if p.suffix in ('.timer', '.service')}


def install(before, after, *, recover=False):
    changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    # Disarm changed timers before replacing files; stop removed services and their children.
    stop = sorted(name for name in before if name in changed and (name.endswith('.timer') or name not in after))
    if stop:
        cmd(['systemctl', 'stop', *stop])

    for name in sorted(changed):
        if name in after:
            template.write(UNITS / name, after[name])
        else:
            (UNITS / name).unlink(missing_ok=True)

    if changed or (recover and after):
        cmd(['systemctl', 'daemon-reload'])

    timers = sorted(name for name in after if name.endswith('.timer') and (recover or name in changed))
    if timers:
        cmd(['systemctl', 'start', *timers])


def reconcile(owner, desired, *, recover=False):
    """Reconcile only this owner's units. Restore its previous schedule if an apply fails."""
    before = installed(owner)
    if any(not re.fullmatch(rf'nvyr-task-{owner}-(?:exec|op)-[A-Za-z0-9][A-Za-z0-9_-]{{0,62}}\.(?:service|timer)', name)
           for name in desired):
        raise ValueError(f'Task unit does not belong to {owner}')

    if desired:
        LOGS.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        install(before, desired, recover=recover)
    except (OSError, RouterError) as error:
        try:
            install(installed(owner), before, recover=True)
        except (OSError, RouterError) as rollback:
            raise RecoveryError(f'Could not restore {owner} tasks: {rollback}') from error
        raise RouterError(f'Could not install {owner} tasks: {error}') from error
