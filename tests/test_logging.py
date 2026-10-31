"""File routing, scoped commands, NFLOG ownership and rotation contracts."""

from copy import deepcopy
import json
import os
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import logging as logging_script
from nvyr.errors import OperationalError, RouterError, ValidationError
from nvyr.helpers import log_reader, logging_formatters, logging_runtime, nftables_lifecycle
from tests.container_rendering import container_unit
from nvyr.op_scripts import logs
from nvyr.schema import Schema
from tests.lifecycle import firewall_context
from tests.test_firewall_enhancements import render


# The suite's host-isolation fixture replaces these service entry points.
# Capture them before fixtures run so these tests can exercise their real logic
# with only external processes and filesystem locations substituted.
INSTALL_LOGGING = logging_runtime.install
PREPARE_GROUPS = logging_runtime.prepare_groups


def test_nflog_identifiers_are_stable_and_do_not_reuse_deleted_groups():
    configuration = {'firewall': {'group': {'log-group': {'NEW': {}, 'KEPT': {}}},
                                  'fail-safe': {'group': {'log-group': {'NEW': {}}}}}}
    previous = {'normal:KEPT': 4, 'normal:DELETED': 1}
    allocated = logging_runtime.identities(configuration, previous)

    assert allocated['normal:KEPT'] == 4
    assert allocated['normal:DELETED'] == 1
    assert len(set(allocated.values())) == 4
    assert allocated['normal:NEW'] != allocated['failsafe:NEW']
    assert previous == {'normal:KEPT': 4, 'normal:DELETED': 1}


def test_group_generation_and_verification(tmp_path):
    tree = {'firewall': {'group': {'log-group': {'DROPS': {'snaplen': '128', 'queue-threshold': '2'}}},
                         'ipv4': {'input': {'filter': {'rule': {
                             '10': {'action': 'drop', 'log': {'group': 'DROPS'}}}}}}}}
    text = render(tree, state_directory=tmp_path)
    assert 'log prefix "[ipv4-INP-filter-10-D]" group 1 snaplen 128 queue-threshold 2' in text
    assert '$log_' not in text

    rule = tree['firewall']['ipv4']['input']['filter']['rule']['10']
    rule['log']['level'] = 'warn'
    with pytest.raises(ValidationError, match='cannot be combined'):
        render(tree)
    rule['log'] = {'group': 'UNKNOWN'}
    with pytest.raises(ValidationError, match='not configured'):
        render(tree)


def test_rendered_nflog_groups_retain_registry_ids_and_scopes(tmp_path):
    """Normal and fail-safe groups with the same name use distinct subscriptions."""
    from nvyr.config_scripts import firewall_failsafe
    from tests.test_firewall_failsafe import context

    group = {'group': {'log-group': {'TEST': {}}}, 'ipv4': {'input': {'filter': {
        'rule': {'10': {'action': 'accept', 'log': {'group': 'TEST'}}}}}}}
    tree = {'firewall': deepcopy(group)}
    tree['firewall']['fail-safe'] = deepcopy(group)

    state = tmp_path / 'logging'
    state.mkdir()
    registry = state / 'groups.json'
    original = json.dumps({'normal:TEST': 37, 'failsafe:TEST': 41})
    registry.write_text(original)

    normal = render(tree, state_directory=tmp_path)
    early_context = context(tree, tmp_path)
    early = firewall_failsafe.generate(firewall_failsafe.get_config(early_context), early_context)

    assert 'group 37 snaplen 65535 queue-threshold 1' in normal
    assert 'group 41 snaplen 65535 queue-threshold 1' in early
    assert 'group 41 ' not in normal
    assert 'group 37 ' not in early
    assert registry.read_text() == original


def test_group_change_rebuilds_consuming_named_chain_and_nested_callers():
    before = {'firewall': {'group': {'log-group': {'TEST': {}}}, 'ipv4': {
        'input': {'filter': {'rule': {'1': {'action': 'jump', 'jump-target': 'OUTER'}}}},
        'name': {'OUTER': {'rule': {'1': {'action': 'jump', 'jump-target': 'INNER'}}},
                 'INNER': {'rule': {'10': {'action': 'accept', 'log': {'group': 'TEST'}}}}}}}}
    after = deepcopy(before)
    after['firewall']['group']['log-group']['TEST']['snaplen'] = '512'
    context = firewall_context(after, before, 'firewall', ('firewall',), previous_effective=before)
    plan = nftables_lifecycle.plan(context, None)

    assert {('chain', 'ipv4_name_INNER'), ('chain', 'ipv4_name_OUTER'),
            ('chain', 'ipv4_input'), ('chain', 'input')} <= plan['rebuild']


def test_rule_scope_is_exact_across_family_hook_stage_and_rule_number(tmp_path):
    directory = tmp_path / 'firewall'
    directory.mkdir()
    lines = ['[ipv4-INP-filter-10-A] wanted', '[ipv6-INP-filter-10-A] wrong family',
             '[ipv4-OUT-filter-10-A] wrong hook', '[ipv4-INP-filter-100-A] wrong rule',
             '[ipv4-INP-filter-default-D] default', '[ipv4-name_INPUT-10-A] named']
    (directory / 'default.log').write_text('\n'.join(lines) + '\n')
    (directory / 'group-TEST.log').write_text('[ipv4-INP-filter-10-D] wanted group\n')
    paths, pattern = log_reader.select('firewall', root=tmp_path, family='ipv4',
                                       hook='input', stage='filter', rule='10')

    result = [line for _, line in log_reader.records(paths, pattern)]
    assert result == ['[ipv4-INP-filter-10-A] wanted\n', '[ipv4-INP-filter-10-D] wanted group\n']


def test_follow_keeps_partial_lines_and_continues_after_rotation(tmp_path):
    path = tmp_path / 'system.log'
    path.write_text('first\npart')
    step = 0

    def tick(_):
        nonlocal step
        step += 1
        if step == 1:
            with path.open('a') as stream:
                stream.write('ial\n')
        elif step == 2:
            path.rename(tmp_path / 'system.log.1')
            path.write_text('rotated\n')
        elif step > 5:
            raise AssertionError('Follower did not reopen the rotated file')

    stream = log_reader.records(lambda: [path], follow=True, sleep=tick)
    try:
        assert next(stream)[1] == 'first\n'
        assert next(stream)[1] == 'partial\n'
        assert next(stream)[1] == 'rotated\n'
    finally:
        stream.close()


def test_reader_rejects_paths_and_symlinks(tmp_path):
    with pytest.raises(OperationalError, match='identifier'):
        log_reader.select('container', root=tmp_path, name='../secrets')
    (tmp_path / 'system.log').symlink_to('/etc/passwd')
    paths, pattern = log_reader.select('system', root=tmp_path)
    with pytest.raises(OSError):
        list(log_reader.records(paths, pattern))


def test_container_logs_exclude_host_service_activity(tmp_path):
    folder = tmp_path / 'containers'
    folder.mkdir()
    (folder / '444e53.service.log').write_text('Started DNS service\n')
    (folder / 'DNS.log').write_text('2026-10-27T12:00:00Z stdout F application ready\n')

    paths, pattern = log_reader.select('container', root=tmp_path, name='DNS')
    output = [log_reader.container_line(line) for _, line in log_reader.records(paths, pattern)]
    assert output == ['2026-10-27T12:00:00Z stdout: application ready\n']


def test_rotation_and_service_thresholds_are_global():
    configuration = {'system': {'logging': {'level': 'warn', 'service': {'bgp': {'level': 'debug'}},
                                           'rotation': {'size': '64m', 'count': '7'}}}}
    files = logging_formatters.render(configuration['system']['logging'])
    collector = files['rsyslog']
    assert 'if $syslogseverity <= 7 then action(type="omfile" file="/var/log/nvyr/bgp.log"' in collector
    assert 'if $syslogseverity <= 4 then action(type="omfile" file="/var/log/nvyr/ntp.log"' in collector
    rotation = files['logrotate']
    assert 'size 64M' in rotation and 'rotate 7' in rotation
    assert 'copytruncate' not in rotation
    assert '/usr/bin/nvyr-logging reopen' in rotation


def test_container_log_path_preserves_native_command_and_startup_identity():
    text = container_unit('DNS', {}, 'alpine')
    assert 'LogDriver=k8s-file' in text
    assert 'LogOpt=path=/var/log/nvyr/containers/DNS.log' in text
    assert 'SyslogIdentifier=nvyr-container-444e53' in text
    assert '\nExec=' not in text


def test_frr_logging_ownership_preserves_static_and_bgp():
    original = 'log syslog informational\nip route 192.0.2.0/24 Null0\nrouter bgp 65000\n bgp router-id 192.0.2.1\nend\n'
    adapter = logging_runtime.FrrLogging()
    desired = {'global': ['log syslog']}
    result = adapter.replace(original, desired)
    assert 'ip route 192.0.2.0/24 Null0' in result
    assert 'router bgp 65000\n bgp router-id 192.0.2.1' in result
    assert adapter.select(result, ['global']) == desired


def test_logging_empty_output_is_readable(monkeypatch, tmp_path, capsys):
    original = log_reader.select
    monkeypatch.setattr(log_reader, 'select', lambda *args, **kwargs: original(*args, root=tmp_path, **kwargs))
    logs.show('system')
    assert capsys.readouterr().out == 'No matching log entries.\n'


def test_operational_scopes_and_follow_dispatch():
    # Parse directly: these paths require an explicit rule number and keep the
    # existing stream/pager execution path rather than adding a lines option.
    schema = Schema.bundled('operational')
    from nvyr.lexer import lex
    cursor = schema.operational(lex('show log firewall ipv4 input filter rule 10'))
    assert cursor.node['command']['argv'][-2:] == ['--rule', '@8']
    followed = schema.operational(lex('show log firewall ipv6 output raw rule 10 follow'))
    assert followed.node['command']['argv'][-1] == '--follow'
    assert followed.node['command']['stream'] is True


def test_operator_dispatches_exact_log_scope_in_both_cli_modes(controller, session):
    """Reading and following logs use the existing privileged stream boundary."""
    from nvyr.helpers import access

    token = access.role.set('read-only')
    try:
        line = 'show log firewall ipv4 input filter rule 10 follow'
        expected = ['logs.nvyr.op', 'show', 'firewall', '--family', 'ipv4',
                    '--hook', 'input', '--stage', 'filter', '--rule', '10', '--follow']
        result = controller.execute(line)
        assert result['event'] == 'command'
        assert result['argv'] == expected
        controller.authorize_terminal(line, None)
    finally:
        access.role.reset(token)

    # Operators can read logs, but only configuration roles can enter run mode.
    result = controller.execute('run ' + line, session)
    assert result['argv'] == expected
    controller.authorize_terminal('run ' + line, session)


def test_named_chain_and_nat_scopes_keep_distinct_prefixes(tmp_path):
    directory = tmp_path / 'firewall'
    directory.mkdir()
    (directory / 'default.log').write_text(
        '[ipv4-name_LAN-10-D] named\n'
        '[ipv4-name_LAN_EXTRA-10-D] another chain\n'
        '[ipv4-PRE-10-D] destination nat\n'
        '[ipv4-POST-10-S] source nat\n'
        '[ipv4-PRE-100-D] another rule\n')

    paths, pattern = log_reader.select('firewall', root=tmp_path, family='ipv4', chain='LAN', rule='10')
    assert [line for _, line in log_reader.records(paths, pattern)] == ['[ipv4-name_LAN-10-D] named\n']

    paths, pattern = log_reader.select('nat', root=tmp_path, direction='destination', rule='10')
    assert [line for _, line in log_reader.records(paths, pattern)] == ['[ipv4-PRE-10-D] destination nat\n']


def test_group_collectors_start_without_global_logging_configuration(tmp_path, monkeypatch):
    """A log group alone starts a subscriber before its rules can be installed."""
    configuration = {'firewall': {'group': {'log-group': {'TEST': {}}}}}
    commands = []
    ready = []
    monkeypatch.setattr(logging_runtime, 'RUNTIME', tmp_path)
    monkeypatch.setattr(logging_runtime, '_directories', lambda: None)
    monkeypatch.setattr(logging_runtime, 'cmd', lambda argv: commands.append(argv))
    monkeypatch.setattr(logging_runtime, 'wait_for_group', ready.append)

    PREPARE_GROUPS(configuration, tmp_path)

    identifier = logging_runtime.registry(tmp_path)['normal:TEST']
    assert ready == [identifier]
    assert commands == [['systemctl', 'restart', f'nvyr-nflog@{identifier}.service']]
    assert (tmp_path / f'nflog-{identifier}.conf').is_file()


def test_readiness_requires_the_collectors_kernel_subscription(tmp_path, monkeypatch):
    """Another process binding the same group must not count as our readiness."""
    path = tmp_path / 'nfnetlink_log'
    path.write_text('1 99 0 2 65531 100 1\n')
    monkeypatch.setattr(logging_runtime, 'NFLOG_STATUS', path)
    monkeypatch.setattr(logging_runtime, 'cmd', lambda argv: '123\n')
    clock = iter((0, 0, 4))
    monkeypatch.setattr(logging_runtime.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(logging_runtime.time, 'sleep', lambda duration: None)

    with pytest.raises(RouterError, match='did not bind'):
        logging_runtime.wait_for_group(1)

    path.write_text('1 123 0 2 65531 100 1\n')
    monkeypatch.setattr(logging_runtime.time, 'monotonic', lambda: 0)
    logging_runtime.wait_for_group(1)


def test_failed_logging_apply_restores_previous_collector_configuration(monkeypatch, tmp_path):
    from nvyr.helpers import frr_reload

    previous = {'system': {'logging': {'level': 'warn'}}}
    desired = {'system': {'logging': {'level': 'debug'}}}
    installed = []
    monkeypatch.setattr(logging_runtime, 'install', installed.append)

    def reject(*args, **kwargs):
        raise RouterError('FRR reload failed')

    prepared = logging_script.generate({'logging': desired['system']['logging'],
                                        'previous': previous['system']['logging']}, None)
    monkeypatch.setattr(frr_reload.manager, 'apply', reject)

    with pytest.raises(RouterError, match='previous configuration restored'):
        logging_script.apply(prepared, SimpleNamespace(state_directory=tmp_path))

    assert installed == [prepared['files'], prepared['previous_files']]


def test_logging_lifecycle_prepares_files_before_apply(monkeypatch, tmp_path):
    from nvyr.helpers import frr_reload
    from nvyr.tree import ReadOnlyTree

    context = SimpleNamespace(
        effective=ReadOnlyTree({'system': {'logging': {'level': 'debug'}}, 'interfaces': {'dummy': {}}}),
        previous_effective=ReadOnlyTree({'system': {'logging': {'level': 'warn'}}}),
        state_directory=tmp_path,
    )
    configuration = logging_script.get_config(context)
    assert set(configuration) == {'logging', 'previous'}
    logging_script.verify(configuration, context)
    prepared = logging_script.generate(configuration, context)
    original = deepcopy(prepared)
    installed = []
    contributions = []

    def unexpected_render(*args, **kwargs):
        pytest.fail('apply must consume already-rendered files')

    monkeypatch.setattr(logging_formatters, 'render', unexpected_render)
    monkeypatch.setattr(logging_runtime, 'install', installed.append)
    monkeypatch.setattr(frr_reload.manager, 'apply', lambda *args, **kwargs: contributions.append(args))

    logging_script.apply(prepared, SimpleNamespace(state_directory=tmp_path))

    assert installed == [prepared['files']]
    assert contributions == [('logging', {'global': ['log syslog']}, tmp_path)]
    assert prepared == original
    assert '$syslogseverity <= 7' in prepared['files']['rsyslog']
    assert '$syslogseverity <= 4' in prepared['previous_files']['rsyslog']


def test_logging_rejects_empty_service_override():
    with pytest.raises(ValidationError, match='system logging service bgp: level is required'):
        logging_script.verify({'logging': {'service': {'bgp': {}}}}, None)


def test_logging_install_validates_before_replacing_files(monkeypatch, tmp_path):
    files = logging_formatters.render({'level': 'debug'})
    collector = tmp_path / 'rsyslog.conf'
    rotation = tmp_path / 'logrotate.conf'
    collector.write_text('old collector')
    rotation.write_text('old rotation')
    commands = []

    def reject(command):
        commands.append(command)
        raise RouterError('Invalid collector configuration')

    monkeypatch.setattr(logging_runtime, 'RUNTIME', tmp_path)
    monkeypatch.setattr(logging_runtime, '_directories', lambda: None)
    monkeypatch.setattr(logging_runtime, 'cmd', reject)

    with pytest.raises(RouterError, match='Invalid collector configuration'):
        INSTALL_LOGGING(files)

    assert commands == [['rsyslogd', '-N1', '-f', str(tmp_path / 'rsyslog.check.conf')]]
    assert collector.read_text() == 'old collector'
    assert rotation.read_text() == 'old rotation'


def test_logging_install_avoids_restart_for_rotation_only_change(monkeypatch, tmp_path):
    initial = logging_formatters.render({})
    (tmp_path / 'rsyslog.conf').write_text(initial['rsyslog'])
    files = logging_formatters.render({'rotation': {'count': '20'}})
    commands = []
    monkeypatch.setattr(logging_runtime, 'RUNTIME', tmp_path)
    monkeypatch.setattr(logging_runtime, '_directories', lambda: None)
    monkeypatch.setattr(logging_runtime, 'cmd', commands.append)

    INSTALL_LOGGING(files)

    assert commands[-1] == ['systemctl', 'start', 'rsyslog.service']
    assert (tmp_path / 'logrotate.conf').read_text() == files['logrotate']


def test_logging_reports_failed_restoration(monkeypatch, tmp_path):
    prepared = logging_script.generate({'logging': {'level': 'debug'}, 'previous': {}}, None)
    attempts = []

    def reject(files):
        attempts.append(files)
        raise RouterError('collector unavailable')

    monkeypatch.setattr(logging_runtime, 'install', reject)

    with pytest.raises(RouterError, match='restoration failed: collector unavailable'):
        logging_script.apply(prepared, SimpleNamespace(state_directory=tmp_path))

    assert attempts == [prepared['files'], prepared['previous_files']]


def test_logging_boot_preparation_uses_default_templates(monkeypatch):
    import sys

    installed = []
    monkeypatch.setattr(sys, 'argv', ['nvyr-logging', 'prepare'])
    monkeypatch.setattr(logging_runtime, 'install', lambda files, **kwargs: installed.append((files, kwargs)))

    logging_runtime.main()

    assert installed == [(logging_formatters.render({}), {'activate': False})]


def test_rotation_reopens_other_writers_even_when_one_fails(monkeypatch):
    calls = []

    def run(argv):
        calls.append(argv)
        if argv[-1] == 'rsyslog.service':
            raise RouterError('rsyslog is not running')
        if argv[1] == 'list-units':
            return 'nvyr-nflog@1.service loaded active running NFLOG\n'
        return ''

    monkeypatch.setattr(logging_runtime, 'cmd', run)
    monkeypatch.setattr(logging_runtime, 'reopen_containers', lambda: calls.append('containers'))
    with pytest.raises(RouterError, match='rsyslog is not running'):
        logging_runtime.reopen()
    assert calls[-2][-1] == 'nvyr-nflog@1.service'
    assert calls[-1] == 'containers'


def test_container_rotation_uses_native_conmon_control_fifo(tmp_path, monkeypatch):
    """Only the managed running container's configured log gets reopened."""
    fifo = tmp_path / 'ctl'
    os.mkfifo(fifo)
    reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    monkeypatch.setattr(logging_runtime, 'LOGS', tmp_path)

    def run(argv):
        if argv[1] == 'ps':
            return json.dumps([{'Id': 'abc'}])
        return json.dumps([{'Name': 'DNS', 'StaticDir': str(tmp_path),
                            'HostConfig': {'LogConfig': {'Path': str(tmp_path / 'containers' / 'DNS.log')}},
                            'State': {'Running': True}}])

    try:
        logging_runtime.reopen_containers(run)
        assert os.read(reader, 1024) == b'2 0 0\n'
    finally:
        os.close(reader)
