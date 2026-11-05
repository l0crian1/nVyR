"""Check scheduling boundaries that a successful systemd run alone cannot exercise."""

import pytest

from nvyr.config_scripts import system_task
from nvyr.errors import RouterError
from nvyr.helpers import task_commands, task_schedule
from nvyr.op_scripts import tasks
from tests.test_login import as_role


def test_exec_cannot_be_changed_through_parent_or_replace(controller, session):
    with as_role('sys-admin'):
        controller.execute("set system task audit exec 'id -u'", session)
        controller.execute('set system task audit interval 6h', session)
        controller.execute('commit', session)
    with as_role('net-admin'):
        for line in ('set system task audit disable', 'delete system task', 'set system task audit interval 2s',
                     'set system task other exec true'):
            with pytest.raises(RouterError, match='sys-admin'):
                controller.execute(line, session)
        with pytest.raises(RouterError, match='sys-admin'):
            controller.engine.stage_configuration(session, {}, replace=True)
        controller.execute("set system task report op-command 'show uptime'", session)
        controller.execute('set system task report interval 8h', session)
        controller.execute('commit', session)


def test_quoted_completion_and_unattended_grammar(controller, session):
    prefix = "set system task TEST op-command 'update firewall ge"
    assert 'update firewall geoip' in dict(controller.completion(prefix, session, tab=True)['candidates'])
    assert task_commands.resolve('update firewall geoip')[0] == ['geoip.nvyr.op', 'update']
    assert task_commands.resolve('show log task example') == (['tasks.nvyr.op', 'logs', 'example'], 15)
    for line in ('shell', 'shellcmd id', 'connect container web', 'show log system follow',
                 'show version | commands', 'configure', 'reboot', 'show'):
        with pytest.raises(RouterError):
            task_commands.resolve(line)


@pytest.mark.parametrize('task', [
    {'interval': '1h'}, {'exec': 'date', 'op-command': 'show date', 'interval': '1h'},
    {'exec': 'date', 'interval': '1h', 'calendar': {'at': ['00:00']}},
    {'exec': 'date', 'calendar': {'day-of-month': ['last']}},
])
def test_ambiguous_or_incomplete_task(task):
    with pytest.raises(RouterError, match='system task TEST'):
        system_task.verify({'TEST': task}, None)


def test_namespace_and_failure_compensation(tmp_path, monkeypatch):
    monkeypatch.setattr(task_schedule, 'UNITS', tmp_path)
    monkeypatch.setattr(task_schedule, 'LOGS', tmp_path / 'logs')
    calls = []
    monkeypatch.setattr(task_schedule, 'cmd', lambda argv: calls.append(argv))
    first = task_schedule.render('system', 'a', 'op', ['date'], {'interval': '6h'})
    other = task_schedule.render('feed', 'a', 'op', ['date'], {'interval': '1d'})
    task_schedule.reconcile('system', first)
    task_schedule.reconcile('feed', other)
    calls.clear()
    task_schedule.reconcile('system', first)
    assert not calls

    def fail_once(argv):
        if argv[1] == 'start' and not calls:
            calls.append(argv)
            raise RouterError('injected start failure')

    monkeypatch.setattr(task_schedule, 'cmd', fail_once)
    with pytest.raises(RouterError, match='injected start failure'):
        task_schedule.reconcile('system', first | task_schedule.render('system', 'b', 'op', ['date'], {'interval': '1h'}))
    assert task_schedule.installed('system') == first
    assert task_schedule.installed('feed') == other


def test_manual_exec_and_logs_require_shell_task_role(monkeypatch):
    monkeypatch.setattr(tasks, 'selected', lambda name: ('exec', 'nvyr-task-system-exec-x'))
    monkeypatch.setenv('NVYR_CALLER_ROLE', 'net-admin')
    for action in (tasks.start, tasks.logs):
        with pytest.raises(RouterError, match='sys-admin'):
            action('x')
