"""Reference inspection uses the same candidate view and declarations as deletion guards."""

import pytest

from nvyr.errors import RouterError, SessionExpiredError, ValidationError
from nvyr.helpers.dependencies import Dependencies
from nvyr.schema import Schema
from nvyr.protocol import Client
from tests.test_integration import daemon
from tests.test_login import as_role


RULE = 'firewall ipv4 forward filter rule 10'


def test_inspection_merges_running_and_own_candidate(controller, engine, session, monkeypatch):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set interfaces dummy dum1', session)
    controller.execute(f'set {RULE} action accept inbound-interface dum0 outbound-interface dum0', session)
    engine.commit(session)
    other = engine.open('other', 'test', draft=True)

    controller.execute(f'delete {RULE} inbound-interface dum0', session)
    controller.execute('set nat source rule 20 outbound-interface dum0', session)
    controller.execute('set nat source rule 30 outbound-interface dum0', other)
    before = tuple(session.mutations)
    monkeypatch.setattr(engine, 'view', lambda *args: pytest.fail('Inspection should use projected reads'))

    text = controller.execute('show references interfaces dummy dum0', session)['text']
    assert text == (f'Referenced by:\n  {RULE} outbound-interface dum0\n'
                    '  nat source rule 20 outbound-interface dum0\n')
    assert tuple(session.mutations) == before
    assert controller.execute('show references interfaces dummy dum1', session)['text'] == 'No references found.\n'

    # One session's staged deletion never hides references from another session.
    other_text = controller.execute('show references interfaces dummy dum0', other)['text']
    assert f'{RULE} inbound-interface dum0' in other_text
    assert 'rule 30' in other_text and 'rule 20' not in other_text

    engine.discard(session)
    assert f'{RULE} inbound-interface dum0' in controller.execute('show references interfaces dummy dum0', session)['text']


def test_edit_abbreviations_and_filters(controller, session):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute(f'set {RULE} inbound-interface dum0 outbound-interface dum0', session)
    controller.execute('edit interfaces', session)

    text = controller.execute('sho ref dum dum0 | match outbound | no-more', session)
    assert text['text'] == f'  {RULE} outbound-interface dum0\n'
    assert text['paging'] is False

    controller.execute('edit dummy dum0', session)
    assert controller.execute('show references', session)['text'].startswith('Referenced by:\n')


@pytest.mark.parametrize('path, message', [
    ('', 'requires a tag-node instance'),
    ('interfaces', 'requires a tag-node instance'),
    ('interfaces dummy', 'Specify the tag-node instance'),
    ('interfaces dummy dum0 mtu', 'requires a tag-node instance'),
    ('interfaces dummy dum0 disable', 'requires a tag-node instance'),
    ('firewall ipv4 forward filter rule 10', 'does not register dependencies'),
    ('interfaces dummy dum999', 'Object is not configured'),
])
def test_invalid_inspection_targets(controller, session, path, message):
    controller.execute('set interfaces dummy dum0', session)
    with pytest.raises(ValidationError, match=message):
        controller.execute(f'show references {path}', session)


def test_deleted_provider_is_not_inspectable_or_completed(controller, session):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('commit', session)
    controller.execute('delete interfaces dummy dum0', session)

    with pytest.raises(ValidationError, match='Object is not configured'):
        controller.execute('show references interfaces dummy dum0', session)

    choices = dict(controller.completion('show references interfaces dummy ', session, explicit=True)['candidates'])
    assert 'dum0' not in choices
    assert '<Enter>' not in dict(controller.completion('show references interfaces dummy dum0 ', session, explicit=True)['candidates'])


def test_reference_completion_uses_only_provider_paths(controller, session):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set firewall ipv4 name CUSTOM', session)

    assert controller.completion('show ref', session, tab=True)['replacement'] == 'references'
    choices = dict(controller.completion('show references ', session, explicit=True)['candidates'])
    assert set(choices) == {'firewall', 'interfaces', 'vrf', 'container', 'policy'}
    assert set(dict(controller.completion('show references firewall ipv4 ', session, explicit=True)['candidates'])) == {'name'}
    assert controller.completion('show references interfaces dummy dum', session, tab=True)['replacement'] == 'dum0'
    assert '<Enter>' not in dict(controller.completion('show references interfaces dummy ', session, explicit=True)['candidates'])
    assert dict(controller.completion('show references interfaces dummy dum0 ', session, explicit=True)['candidates']) == {
        '<Enter>': 'Execute the current command'}
    assert '<Enter>' in dict(controller.completion('show references interfaces dummy dum0', session, explicit=True)['candidates'])

    controller.execute('edit interfaces', session)
    choices = dict(controller.completion('show references ', session, explicit=True)['candidates'])
    assert set(choices) == {'ethernet', 'dummy', 'virtual-ethernet', 'bridge', 'loopback'}


def test_named_chains_are_family_specific_and_guarded(controller, engine, session):
    for family in ('ipv4', 'ipv6'):
        controller.execute(f'set firewall {family} name CUSTOM', session)
    paths = [f'{RULE} jump-target', 'firewall ipv4 prerouting raw rule 2 jump-target',
             'firewall ipv4 name PARENT rule 3 jump-target']
    for path in paths:
        controller.execute(f'set {path} CUSTOM', session)

    text = controller.execute('show references firewall ipv4 name CUSTOM', session)['text']
    assert set(text.splitlines()[1:]) == {f'  {path} CUSTOM' for path in paths}
    assert controller.execute('show references firewall ipv6 name CUSTOM', session)['text'] == 'No references found.\n'
    controller.execute('delete firewall ipv6 name CUSTOM', session)

    before = tuple(session.mutations)
    for command in ('delete firewall ipv4 name CUSTOM',
                    'rename firewall ipv4 name CUSTOM to firewall ipv4 name NEW'):
        with pytest.raises(ValidationError, match='referenced by') as error:
            controller.execute(command, session)
        assert all(path in str(error.value) for path in paths)
        assert tuple(session.mutations) == before

    # Removing providers and consumers together still works as one mutation.
    controller.execute('delete firewall', session)
    assert engine.view(session).get('firewall') is None


def test_ipv6_reference_does_not_block_ipv4_provider(controller, session):
    controller.execute('set firewall ipv4 name CUSTOM', session)
    controller.execute('set firewall ipv6 name CUSTOM', session)
    controller.execute('set firewall ipv6 input filter rule 10 jump-target CUSTOM', session)

    assert 'ipv6 input filter rule 10 jump-target CUSTOM' in controller.execute('show references firewall ipv6 name CUSTOM', session)['text']
    controller.execute('delete firewall ipv4 name CUSTOM', session)
    with pytest.raises(ValidationError, match='firewall-chain-ipv6'):
        controller.execute('delete firewall ipv6 name CUSTOM', session)


def test_generic_tag_consumers_quotes_and_replaced_references(controller, engine, session):
    engine.schema = Schema({'kind': 'node', 'children': {
        'objects': {'kind': 'tag_node', 'dependency': 'object', 'script': {'name': 'objects', 'priority': 1}},
        'users': {'kind': 'tag_node', 'depends': 'object', 'script': {'name': 'users', 'priority': 2}},
        'uses': {'kind': 'leaf_node', 'depends': 'object', 'script': {'name': 'uses', 'priority': 3}},
    }})
    engine.dependencies = Dependencies(engine.schema)
    controller.execute('set objects "object one"', session)
    controller.execute('set users "object one"', session)
    controller.execute('set uses "object one"', session)
    controller.execute('set uses other', session)

    assert controller.execute('show references objects "object one"', session)['text'] == "Referenced by:\n  users 'object one'\n"


def test_permissions_and_expiry(controller, engine, session):
    controller.execute('set interfaces dummy dum0', session)
    with as_role('read-only'):
        with pytest.raises(RouterError, match='Permission denied'):
            controller.execute('show references interfaces dummy dum0', session)
        with pytest.raises(RouterError, match='Permission denied'):
            engine.references(session, ['interfaces', 'dummy', 'dum0'])

    with as_role('net-admin'):
        assert controller.execute('show references interfaces dummy dum0', session)['text'] == 'No references found.\n'

    with pytest.raises(RouterError):
        controller.execute('show references interfaces dummy dum0')

    engine.close(session, expired=True)
    with pytest.raises(SessionExpiredError):
        controller.execute('show references interfaces dummy dum0', session)


def test_reference_inspection_over_rpc(daemon):
    client = Client(daemon)
    try:
        client.request('open')
        client.request('execute', text='set interfaces dummy dum0')
        client.request('execute', text=f'set {RULE} inbound-interface dum0')
        assert client.request('execute', text='show references interfaces dummy dum0')['text'] == f'Referenced by:\n  {RULE} inbound-interface dum0\n'
    finally:
        client.close()
