"""Exercise timer execution, output, manual starts and overlap on one shared schedule.

Uses two uniquely named tasks. No traffic, external services or clock changes required.
"""

from uuid import uuid4

from nvyr.helpers import task_schedule
from smoketests.assertions import assert_operational_output
from smoketests.support import configuration_case, wait_for


def test_scheduled_and_manual_runs(config, request):
    suffix = uuid4().hex[:8]
    shell, op = 'test-shell-' + suffix, 'test-op-' + suffix
    shell_log = task_schedule.LOGS / (task_schedule.unit('system', 'exec', shell) + '.log')
    op_log = task_schedule.LOGS / (task_schedule.unit('system', 'op', op) + '.log')

    with configuration_case(config, request, config.get_config()):
        config.set(f"set system task {shell} exec 'echo started; sleep 2; echo finished'")
        config.set(f'set system task {shell} interval 1d')
        config.set(f"set system task {op} op-command 'show uptime'")
        config.set(f'set system task {op} interval 1s')
        config.commit()

        assert_operational_output('start system task ' + shell, 'Start requested')
        wait_for(lambda: shell_log.exists() and shell_log.read_text(), lambda s: s and 'started' in s,
                 description='first shell invocation')
        assert_operational_output('start system task ' + shell, 'Start requested')
        wait_for(shell_log.read_text, lambda s: 'finished' in s, description='shell completion')
        assert shell_log.read_text().splitlines() == ['started', 'finished']
        wait_for(lambda: op_log.exists() and op_log.read_text(), bool, description='automatic operational task')
        assert_operational_output('show log task ' + shell, 'started', 'finished')
        assert_operational_output('show system tasks ' + shell, 'success')
