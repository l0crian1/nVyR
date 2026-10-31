"""Schema-controlled tag renaming is enforced before candidate mutations."""

from copy import deepcopy
import json

import pytest
import yaml

from build_tools.schema_builder import SchemaBuildError, build_schemas
from nvyr.errors import RouterError, ValidationError
from nvyr.protocol import Client
from nvyr.schema import Schema
from tests.test_integration import daemon


@pytest.mark.parametrize('kind, value', [
    ('tag_node', 'false'), ('tag_node', 0), ('tag_node', 1),
    ('tag_node', None), ('tag_node', []), ('tag_node', {}),
    ('node', False), ('node', True), ('leaf_node', False), ('leaf_node', True),
])
def test_invalid_rename_declaration_rejected_at_build_and_runtime(tmp_path, kind, value):
    document = {'kind': 'node', 'children': {'objects': {'kind': kind, 'rename': value}}}
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'configuration.yaml').write_text(yaml.safe_dump(document))

    with pytest.raises(SchemaBuildError, match='objects: rename requires a boolean on a tag_node'):
        build_schemas(source, tmp_path / 'output')

    with pytest.raises(ValueError, match='objects: rename requires a boolean on a tag_node'):
        Schema(document)


def test_builder_preserves_explicit_policy_and_implicit_default(tmp_path):
    document = {'kind': 'node', 'children': {
        'allowed': {'kind': 'tag_node', 'rename': True},
        'blocked': {'kind': 'tag_node', 'rename': False},
        'implicit': {'kind': 'tag_node'},
    }}
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'configuration.yaml').write_text(yaml.safe_dump(document))
    output = tmp_path / 'output'
    build_schemas(source, output)
    generated = json.loads((output / 'configuration.json').read_text())
    assert generated == document
    Schema(generated)


@pytest.mark.parametrize('edit', [False, True])
def test_vrf_rename_rejected_without_candidate_changes(controller, engine, session, edit):
    controller.execute('set vrf name BLUE table 100', session)
    if edit:
        controller.execute('edit vrf', session)

    source = ['name', 'BLUE'] if edit else ['vrf', 'name', 'BLUE']
    destination = [*source[:-1], 'RED']
    before = deepcopy(engine.view(session))
    mutations = tuple(session.mutations)

    with pytest.raises(ValidationError, match='^Renaming is not supported for: vrf name$'):
        engine.rename(session, source, destination)

    command = f"rename {' '.join(source)} to {' '.join(destination)}"
    with pytest.raises(ValidationError, match='Renaming is not supported for: vrf name'):
        controller.execute(command, session)

    assert engine.view(session) == before
    assert tuple(session.mutations) == mutations
    assert not engine.running


def test_vrf_copy_and_delete_still_work(controller, engine, session):
    controller.execute('set vrf name BLUE table 100', session)
    engine.commit(session)
    controller.execute('edit vrf', session)
    controller.execute('copy name BLUE to name RED', session)
    controller.execute('set name RED table 101', session)
    assert engine.commit(session)['results']['vrf']['success']
    assert engine.running['vrf']['name'] == {'BLUE': {'table': '100'}, 'RED': {'table': '101'}}

    controller.execute('delete name BLUE', session)
    assert engine.commit(session)['results']['vrf']['success']
    assert engine.running['vrf']['name'] == {'RED': {'table': '101'}}


@pytest.mark.parametrize('explicit', [False, True])
def test_other_tags_allow_rename_by_default_or_explicitly(controller, engine, session, explicit):
    node = engine.schema.root['children']['interfaces']['children']['dummy']
    assert 'rename' not in node
    if explicit:
        node['rename'] = True

    controller.execute('set interfaces dummy dum0 description original', session)
    controller.execute('edit interfaces', session)
    controller.execute('rename dummy dum0 to dummy dum1', session)
    assert engine.view(session)['interfaces']['dummy'] == {'dum1': {'description': 'original'}}


def test_policy_does_not_block_child_tag_renames(controller, engine, session):
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set vrf name BLUE protocols static route 192.0.2.0/24 next-hop 198.51.100.1', session)
    controller.execute('edit vrf name BLUE protocols static', session)
    controller.execute('rename route 192.0.2.0/24 to route 203.0.113.0/24', session)
    routes = engine.view(session)['vrf']['name']['BLUE']['protocols']['static']['route']
    assert routes == {'203.0.113.0/24': {'next-hop': {'198.51.100.1': {}}}}


def test_rpc_cannot_bypass_rename_policy(daemon):
    client = Client(daemon)
    try:
        client.request('open')
        client.request('execute', text='set vrf name BLUE table 100')
        with pytest.raises(RouterError, match='Renaming is not supported for: vrf name') as error:
            client.request('execute', text='rename vrf name BLUE to vrf name RED')

        assert error.value.code == ValidationError.code
        config = client.request('get_config', source='candidate')['configuration']
        assert config['vrf']['name'] == {'BLUE': {'table': '100'}}
    finally:
        client.close()
