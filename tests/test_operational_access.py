"""Declarative operational permissions, including inherited and anchored paths."""

import json

import pytest

from build_tools.schema_builder import SchemaBuildError, build_schemas
from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.schema import Schema
from tests.test_login import as_role


@pytest.fixture
def commands(controller, monkeypatch):
    controller.operational = Schema({'kind': 'node', 'children': {
        'inspect': {'kind': 'node', 'command': {'argv': ['inspect']}},
        'maintain': {'kind': 'node', 'access': 'net-admin', 'children': {
            'refresh': {'kind': 'node', 'command': {'argv': ['refresh']}},
            'live': {'kind': 'node', 'command': {'argv': ['live'], 'stream': True}},
            'status': {'kind': 'node', 'access': 'read-only', 'command': {'argv': ['status']}},
            'reset': {'kind': 'node', 'access': 'sys-admin', 'command': {'argv': ['reset']}},
        }},
        'probe': {'kind': 'tag_node', 'anchor': True, 'command': {'argv': ['probe', '@line']}, 'children': {
            'brief': {'kind': 'leaf_node', 'valueless': True},
            'dangerous': {'kind': 'leaf_node', 'valueless': True, 'access': 'sys-admin'},
        }},
    }})
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'done\n')

    return calls


@pytest.mark.parametrize('role', ['read-only', 'net-admin', 'sys-admin', 'dev-admin'])
def test_default_inheritance_and_override(controller, commands, role):
    with as_role(role):
        assert controller.execute('inspect')['text'] == 'done\n'
        assert controller.execute('maintain status')['text'] == 'done\n'

        for command, required in [('maintain refresh', 'net-admin'), ('maintain reset', 'sys-admin')]:
            before = len(commands)

            if access.allows(required):
                assert controller.execute(command)['text'] == 'done\n'
            else:
                with pytest.raises(RouterError, match=f'requires {required} access'):
                    controller.execute(command)

                assert len(commands) == before


def test_help_and_abbreviations_follow_policy(controller, commands):
    with as_role('read-only'):
        assert 'maintain' in dict(controller.completion('', explicit=True)['candidates'])
        assert set(dict(controller.completion('maintain ', explicit=True)['candidates'])) == {'status'}
        assert '<Enter>' not in dict(controller.completion('maintain refresh', explicit=True)['candidates'])
        assert controller.execute('mai sta')['text'] == 'done\n'

        with pytest.raises(RouterError, match='Permission denied'):
            controller.execute('mai ref')


def test_configuration_run_and_terminal_reauthorization(controller, session, commands):
    with as_role('net-admin'):
        assert controller.execute('run maintain refresh', session)['text'] == 'done\n'
        assert controller.execute('run maintain live', session)['event'] == 'command'
        controller.authorize_terminal('run maintain live', session)

        with pytest.raises(RouterError, match='sys-admin'):
            controller.execute('run maintain reset', session)

    with as_role('read-only'):
        with pytest.raises(RouterError, match='net-admin'):
            controller.execute('maintain live')

        with pytest.raises(RouterError, match='net-admin'):
            controller.authorize_terminal('maintain live', None)


def test_anchor_cannot_lose_restricted_option_policy(controller, commands):
    with as_role('read-only'):
        assert controller.execute('probe host brief')['text'] == 'done\n'

        for text in ('probe host dangerous', 'probe host dangerous brief', 'probe host brief dangerous'):
            with pytest.raises(RouterError, match='sys-admin'):
                controller.execute(text)

            assert '<Enter>' not in dict(controller.completion(text, explicit=True)['candidates'])

        assert 'dangerous' not in dict(controller.completion('probe host ', explicit=True)['candidates'])


@pytest.mark.parametrize('value', ['admin', True, None, [], 1])
def test_invalid_access_rejected_in_builder_and_runtime(tmp_path, value):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'operational.yaml').write_text(
        'kind: node\nchildren:\n  test:\n    kind: node\n    access: ' + json.dumps(value) + '\n')

    with pytest.raises(SchemaBuildError, match='test.*invalid access'):
        build_schemas(source, tmp_path / 'out')

    with pytest.raises(ValueError, match='Invalid access.*test'):
        Schema({'kind': 'node', 'children': {'test': {'kind': 'node', 'access': value}}})


def test_builtin_configure_and_draft_inherit_restriction(controller):
    with as_role('read-only'):
        for line in ('configure', 'configure draft'):
            with pytest.raises(RouterError, match='net-admin'):
                controller.execute(line)

        assert 'configure' not in dict(controller.completion('', explicit=True)['candidates'])

    with as_role('net-admin'):
        assert controller.execute('configure')['event'] == 'configure'
        assert controller.execute('configure draft')['event'] == 'configure-draft'
