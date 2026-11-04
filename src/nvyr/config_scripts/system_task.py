"""User-defined scheduled tasks, independent of schedules owned by other features."""

from nvyr.errors import ValidationError
from nvyr.helpers import task_commands, task_schedule
from nvyr.tree import lookup


def get_config(context):
    return lookup(context.effective, ('system', 'task'), {})


def verify(configuration, context):
    for name, task in configuration.items():
        path = f'system task {name}'
        # A service needs one action even when initially disabled.
        if ('exec' in task) == ('op-command' in task):
            raise ValidationError(f'{path}: configure exactly one of exec or op-command')
        # Interval and wall-clock schedules have different timing semantics.
        if ('interval' in task) == ('calendar' in task):
            raise ValidationError(f'{path}: configure exactly one of interval or calendar')
        # Day selectors only narrow the times at which the task runs.
        if 'calendar' in task and not lookup(task, ('calendar', 'at'), ()):
            raise ValidationError(f'{path}: calendar requires at least one time')


def generate(configuration, context):
    files = {}
    for name, task in configuration.items():
        if 'exec' in task:
            kind, argv = 'exec', ['/bin/sh', '-c', task['exec']]
        else:
            kind = 'op'
            argv, timeout = task_commands.resolve(task['op-command'])
            if timeout:
                argv = ['/usr/bin/timeout', '--kill-after=5s', str(timeout), *argv]
        files.update(task_schedule.render('system', name, kind, argv, task))
    return files


def apply(files, context):
    task_schedule.reconcile('system', files, recover=context.recovery)
