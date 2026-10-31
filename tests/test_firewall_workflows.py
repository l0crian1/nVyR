import json
import os
import pty
import select
import signal
import sys
import time

import pytest

from nvyr.config_scripts import firewall
from nvyr.cli import CLI
from nvyr.errors import RouterError
from nvyr.tree import lookup


RULE = '''set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 description "This is a test"
set firewall ipv4 forward filter rule 10 source-address 1.1.1.1/32
set firewall ipv4 forward filter rule 10 destination-address 2.2.2.2/32
set firewall ipv4 forward filter rule 10 destination-port 22
set firewall ipv4 forward filter rule 10 protocol tcp
set firewall ipv4 forward filter rule 10 log'''


def test_firewall_real_lifecycle_uses_shared_effective_tree(controller, engine, session, monkeypatch):
    controller.execute('set interfaces dummy dum0 address 1.1.1.1/32', session)
    engine.commit(session)
    existing_interface = engine.running['interfaces']['dummy']['dum0']
    received = []
    get_config = firewall.get_config

    def capture(context):
        config = get_config(context)

        assert config is context.effective

        # Direct MTU defaults copy the interface mapping, but retain untouched values.
        effective_interface = lookup(config, ('interfaces', 'dummy', 'dum0'))._tree

        assert effective_interface['address'] is existing_interface['address']
        assert effective_interface['mtu'] == '1500' and 'mtu' not in existing_interface

        with pytest.raises(TypeError):
            config['interfaces']['dummy']['dum0']['address'] = []

        received.append(config)

        return config

    monkeypatch.setattr(firewall, 'get_config', capture)
    loaded = []
    monkeypatch.setattr(firewall.nftables.manager, 'apply', lambda text, directory, *, accounting: loaded.append(text))

    for line in RULE.splitlines():
        controller.execute(line, session)

    engine.modules['firewall'].calls.clear()
    output = controller.execute('commit', session)['text']
    assert 'firewall: done' in output and 'Commit 2 completed' in output
    assert [stage for _, stage, _ in engine.modules['firewall'].calls] == ['get_config', 'verify', 'generate', 'apply']
    assert len(received) == 1

    effective = received[0]

    assert tuple(effective['interfaces']['dummy']['dum0']['address']) == ('1.1.1.1/32',)

    filter_ = effective['firewall']['ipv4']['forward']['filter']

    assert filter_['default-action'] == 'accept'
    assert dict(filter_['rule']['10']) == {
        'action': 'accept', 'description': 'This is a test', 'source-address': {'1.1.1.1/32': {}},
        'destination-address': {'2.2.2.2/32': {}}, 'destination-port': ('22',), 'protocol': ('tcp',), 'log': {},
    }
    assert 'th dport { 22 } log prefix "[ipv4-FWD-filter-10-A]" accept comment "10|This is a test"' in loaded[0]
    assert 'counter accept comment "default|default-action accept"' in loaded[0]
    assert 'default-action' not in lookup(engine.running, ('firewall', 'ipv4', 'forward', 'filter'))

    engine.save(session)

    assert engine.store.read('boot.json') == engine.running
    assert engine.store.historical(engine.commit_id, 0) == engine.running
    assert not session.mutations
    assert controller.execute('show candidate-configuration', session)['text'] == '{}\n'


@pytest.mark.parametrize('suffix', [
    'rule zero action accept', 'rule 10 source-address ::1/128',
    'rule 10 destination-address 192.168.1.500/24', 'rule 10 destination-port 65536',
    'rule 10 protocol invalid', 'rule 10 action invalid', 'rule 10 log true',
])
def test_firewall_schema_rejects_invalid_values(controller, session, suffix):
    with pytest.raises(RouterError):
        controller.execute('set firewall ipv4 forward filter ' + suffix, session)

    assert not session.mutations


def test_deleted_parent_then_descendant_is_visible_and_commands_roundtrip(controller, engine, session):
    for suffix in ['address 1.1.1.1/32', 'address 1.1.1.2/32', 'description test123', 'disable']:
        controller.execute('set interfaces dummy dum0 ' + suffix, session)

    engine.commit(session)
    controller.execute('delete interfaces', session)
    text = controller.execute('show candidate-configuration', session)['text']

    assert '-   "interfaces"' in text and 'null' not in text

    controller.execute('set interfaces dummy dum0 description test', session)
    text = controller.execute('show candidate-configuration', session)['text']

    assert '-         "description": "test123"' in text and '+         "description": "test"' in text
    assert '-         "address"' in text and '-         "disable"' in text

    commands = controller.execute('show candidate-configuration | commands', session)['text']
    replay = engine.open('replay', 'test', draft=True)

    for line in commands.splitlines():
        controller.execute(line, replay)

    assert engine.view(replay) == engine.view(session)


def test_show_scope_sources_edit_context_and_typed_pipeline(controller, engine, session):
    controller.execute('set interfaces dummy dum0 description old', session)
    controller.execute('set system host-name untouched', session)
    engine.commit(session)
    controller.execute('set interfaces dummy dum0 description new', session)

    for line in RULE.splitlines():
        controller.execute(line, session)

    scoped = controller.execute('show running-configuration interfaces dummy', session)['text']

    assert json.loads(scoped) == {'dum0': {'description': 'old'}}
    assert 'untouched' not in controller.execute('show candidate-configuration firewall', session)['text']
    assert 'rule' in controller.execute('show fire ipv4 forw filt', session)['text']

    commands = controller.execute('show interfaces dummy dum0 | commands', session)['text']

    assert commands == 'set description new\n'

    running = controller.execute('show running-configuration interfaces dummy dum0 description | commands', session)['text']

    assert running == 'set description old\n'

    controller.execute('edit interfaces dummy dum0', session)

    assert json.loads(controller.execute('show running-configuration description', session)['text']) == 'old'
    assert controller.execute('show description | commands', session)['text'] == commands
    assert json.loads(controller.execute('show running-configuration', session)['text']) == {'description': 'old'}

    controller.execute('delete description', session)

    assert '- "old"' in controller.execute('show candidate-configuration description', session)['text']
    assert controller.execute('show candidate-configuration description | commands', session)['text'] == 'delete description\n'


def test_show_scope_validation_completion_and_empty_tag_deletion(controller, engine, session):
    controller.execute('set interfaces dummy dum0', session)
    engine.commit(session)

    with pytest.raises(RouterError, match='not configured'):
        controller.execute('show interfaces dummy dum999', session)

    with pytest.raises(RouterError):
        controller.execute('show firewall nonsense', session)

    assert {'firewall', 'interfaces', 'running-configuration', 'candidate-configuration'} <= set(dict(controller.completion('show ', session, explicit=True)['candidates']))
    assert controller.completion('show run', session, space=True)['replacement'] == 'running-configuration'
    assert controller.completion('show running-configuration inter', session)['replacement'] == 'interfaces'
    assert controller.completion('show interfaces dummy d', session)['replacement'] == 'dum0'
    assert controller.completion('show interfaces dummy dum0 des', session)['replacement'] == 'description'
    assert '<Enter>' in dict(controller.completion('show interfaces dummy dum0 description', session, explicit=True)['candidates'])
    assert not controller.completion('show interfaces dummy dum0 description ', session)['candidates']

    with pytest.raises(RouterError, match='without a setting value'):
        controller.execute('show interfaces dummy dum0 description value', session)

    controller.execute('edit interfaces dummy dum0', session)

    assert controller.completion('show running-configuration des', session)['replacement'] == 'description'

    controller.execute('top', session)
    controller.execute('delete interfaces', session)

    assert controller.execute('show candidate-configuration interfaces dummy dum0', session)['text'] == '- {}\n'


def test_compare_and_rollback_share_timestamped_retained_history(controller, engine, session):
    controller.execute('set system host-name one', session)
    engine.commit(session)
    compare = dict(controller.completion('compare ', session, explicit=True)['candidates'])
    rollback = dict(controller.completion('rollback ', session, tab=True)['candidates'])

    assert rollback == {key: value for key, value in compare.items() if key not in {'saved', '<Enter>'}}
    assert compare['saved'] == 'Saved configuration'
    assert compare['0'].endswith(' UTC') and len(compare['0']) == 23

    controller.execute('rollback 0', session)

    assert not session.mutations

    controller.execute('rollback 1', session)

    assert engine.view(session) == {}

    engine.store.delete('history/00000000000000000000.json')

    assert '1' not in dict(controller.completion('rollback ', session, explicit=True)['candidates'])


def test_scoped_commands_never_delete_siblings_and_handle_empty_tags(controller, engine, session):
    controller.execute('set interfaces dummy dum0 description remove', session)
    controller.execute('set interfaces dummy dum1 description preserve', session)
    engine.commit(session)
    controller.execute('delete interfaces dummy dum0', session)

    assert controller.execute('show candidate-configuration interfaces dummy dum0 description | commands', session)['text'] == 'delete description\n'
    assert 'dum0' in dict(controller.completion('show running-configuration interfaces dummy ', session, explicit=True)['candidates'])
    assert 'dum0' in dict(controller.completion('show candidate-configuration interfaces dummy ', session, explicit=True)['candidates'])

    controller.execute('set interfaces dummy dum2', session)

    assert controller.execute('show candidate-configuration interfaces dummy dum2 | commands', session)['text'] == 'set dummy dum2\n'
    assert 'dum2' not in dict(controller.completion('show running-configuration interfaces dummy ', session, explicit=True)['candidates'])


def test_shell_event_uses_shared_handler_and_rejects_arguments_or_pipes(controller, session):
    assert controller.execute('shell')['event'] == 'shell'
    assert controller.execute('shell', session)['event'] == 'shell'

    for mode in [None, session]:
        with pytest.raises(RouterError):
            controller.execute('shell ignored', mode)

        with pytest.raises(RouterError):
            controller.execute('shell | count', mode)


def test_interactive_shell_inherits_real_terminal_and_returns(tmp_path):
    marker = tmp_path / 'shell-result'
    pid, descriptor = pty.fork()
    if pid == 0:
        os.environ['SHELL'] = '/bin/sh'

        # Exercise terminal handoff with an authorized role without requiring
        # nVyR Linux groups on the development/CI host.
        os.execv(sys.executable, [sys.executable, '-c',
            'from nvyr import login; login.local_role = lambda: "dev-admin"; '
            'from nvyr.helpers.process import interactive_shell; interactive_shell(); print("NVYR_RETURNED", flush=True)'])

    data = b''

    try:
        # Commands are consumed by the shell on its inherited controlling terminal.
        os.write(descriptor, f'test -t 0 && test -t 1 && echo terminal-ok > {marker}\nexit\n'.encode())
        deadline = time.monotonic() + 10

        while time.monotonic() < deadline:
            if select.select([descriptor], [], [], .1)[0]:
                try:
                    chunk = os.read(descriptor, 65536)
                except OSError:
                    break

                data += chunk

                if b'NVYR_RETURNED' in data:
                    break

        assert b'NVYR_RETURNED' in data
        assert marker.read_text().strip() == 'terminal-ok'
    finally:
        os.close(descriptor)

        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

        os.waitpid(pid, 0)
