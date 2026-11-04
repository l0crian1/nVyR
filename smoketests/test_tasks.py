"""Inspect task calendar translation and disable behavior using the installed CLI."""

from nvyr.helpers import task_schedule
from smoketests.support import configuration_case


def test_task_calendar(config, request):
    with configuration_case(config, request, config.get_config()):
        root = 'system task SMOKE-CALENDAR'
        for leaf in ("op-command 'show uptime'", 'calendar at 03:00', 'calendar at 06:45',
                     'calendar day-of-week weekdays', 'calendar day-of-month 1', 'calendar day-of-month last'):
            config.set(f'set {root} {leaf}')
        config.commit()

        timer = task_schedule.UNITS / 'nvyr-task-system-op-SMOKE-CALENDAR.timer'
        rules = [line for line in timer.read_text().splitlines() if line.startswith('OnCalendar=')]
        assert set(rules) == {f'OnCalendar=Mon,Tue,Wed,Thu,Fri {day} {time}'
                              for day in ('*-*-1', '*-*~01') for time in ('03:00', '06:45')}

        config.set(f'set {root} disable')
        config.commit()
        assert not timer.exists() and timer.with_suffix('.service').exists()
