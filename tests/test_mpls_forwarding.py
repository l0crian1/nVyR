"""MPLS label boundaries, schema validation and ownership across LDP/static/BGP."""

from types import SimpleNamespace

import pytest

from nvyr.config_scripts import protocols_mpls, protocols_static
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import frr_mpls, interfaces, mpls, validators
from tests.test_mpls_ldp import sysctls


@pytest.fixture
def configuration():
    return {'default-ttl': '255'}


def test_full_capacity_when_enabled(controller, session, engine):
    controller.execute('set protocols mpls interface dum91', session)
    result = engine.commit(session)
    assert result['results']['mpls']['success'], result
    effective = protocols_mpls.get_config(type('Context', (), {'effective': engine.schema.defaults(engine.running)})())
    assert protocols_mpls.generate(effective, None)['kernel']['label-table-size'] == 1048575


@pytest.mark.parametrize('tail', ['default-ttl 0', 'lsp 100000', 'lsp 1048574',
                                'lsp 16 next-hop 192.0.2.2 outgoing-label 3'])
def test_bad_leaf_values(controller, session, tail):
    with pytest.raises(RouterError):
        controller.execute('set protocols mpls ' + tail, session)


def test_static_requires_action(configuration):
    configuration['lsp'] = {'16000': {'next-hop': {'192.0.2.2': {}}}}
    with pytest.raises(ValidationError, match='outgoing-label is required'):
        protocols_mpls.verify(configuration, None)


@pytest.mark.parametrize('label,address', [('016000', '192.0.2.2'), ('16000', '2001:db8:0::2')])
def test_duplicate_static_identities(configuration, label, address):
    configuration['lsp'] = {'16000': {'next-hop': {'2001:db8::2': {'outgoing-label': '17000'}}}}
    if label != '16000':
        configuration['lsp'][label] = {'next-hop': {address: {'outgoing-label': '17000'}}}
    else:
        configuration['lsp'][label]['next-hop'][address] = {'outgoing-label': '17000'}
    with pytest.raises(ValidationError, match='duplicate'):
        protocols_mpls.verify(configuration, None)


@pytest.mark.parametrize('family,prefix,hop,label', [
    ('route', '192.0.2.0/24', '198.51.100.1', '16000/2'),
    ('route6', '2001:db8::/64', '2001:db8:1::1', '16000/0'),
])
def test_explicit_null_payload_family(monkeypatch, family, prefix, hop, label):
    monkeypatch.setattr(interfaces, 'local_addresses', lambda vrf=None: set())
    configuration = {'default': {family: {prefix: {'next-hop': {hop: {'label': label}}}}}}
    with pytest.raises(ValidationError, match='explicit-null'):
        protocols_static.verify(configuration, SimpleNamespace(check_only=False))


@pytest.mark.parametrize('value,valid', [('16000/24000', True), ('16000/0', True), ('2', True),
                                       ('0/16000', False), ('3', False), ('16000/', False),
                                       ('1048576', False), ('/'.join(['16000'] * 17), False)])
def test_label_stack(value, valid):
    assert validators.mpls_label_stack(value) == valid


def test_global_adapter_preserves_ldp_and_static():
    original = 'mpls label dynamic-block 100000 1048574\nmpls ldp\n router-id 192.0.2.1\nexit\nip route 192.0.2.0/24 eth1 label 16\nmpls lsp 16 192.0.2.2 17\nend\n'
    replaced = frr_mpls.adapter.replace(original, {'global': ['mpls fec nexthop-resolution']})
    assert 'mpls ldp\n router-id 192.0.2.1\nexit' in replaced
    assert 'ip route 192.0.2.0/24 eth1 label 16' in replaced
    assert 'mpls lsp' not in replaced
    assert 'mpls label dynamic-block 100000 1048574' in replaced
    assert frr_mpls.adapter.select(replaced, ('global',)) == {'global': ['mpls fec nexthop-resolution']}


def test_ttl_settings_and_reset(sysctls):
    mpls.apply({'interfaces': [], 'label-table-size': 1024, 'default-ttl': 64, 'ip-ttl-propagate': 0})
    assert (sysctls / 'default_ttl').read_text() == '64'
    assert (sysctls / 'ip_ttl_propagate').read_text() == '0'
    mpls.apply({'interfaces': [], 'label-table-size': 0})
    assert (sysctls / 'default_ttl').read_text() == '255'
    assert (sysctls / 'ip_ttl_propagate').read_text() == '1'
