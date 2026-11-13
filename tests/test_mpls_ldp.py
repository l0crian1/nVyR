"""MPLS ownership, event replay, schema defaults and LDP translation contracts."""

import pytest

from nvyr.config_scripts import protocols_ldp, protocols_mpls
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import frr_ldp, mpls
from nvyr.helpers.link_manager import Manager
from nvyr.op_scripts import mpls as operational
from tests.test_netlink import Kernel, Leases, Message


def test_schema_defaults_and_pipeline(controller, session, engine):
    controller.execute('set protocols mpls interface dum91', session)
    controller.execute('set protocols ldp options router-id 192.0.2.91', session)
    controller.execute('set protocols ldp address-family ipv4 interface dum91 hello interval 3 holdtime 12', session)
    result = engine.commit(session)
    assert result['results']['mpls']['success'], result
    assert result['results']['ldp']['success'], result


@pytest.mark.parametrize('tail', ['label-table-size 1048575', 'dynamic-label-block 100000-1048574', 'interface ../bad'])
def test_invalid_mpls_cli(controller, session, tail):
    with pytest.raises(RouterError):
        controller.execute('set protocols mpls ' + tail, session)


def test_mpls_generate_uses_effective_default():
    configuration = {'interface': ['dum1'], 'default-ttl': '255'}
    generated = protocols_mpls.generate(configuration, None)
    assert generated['kernel'] == {'interfaces': ['dum1'], 'label-table-size': 1048575,
                                   'ip-ttl-propagate': 1, 'default-ttl': 255}
    assert generated['frr'] == {'global': []}
    assert protocols_mpls.generate(None, None) == {
        'kernel': {'interfaces': [], 'label-table-size': 0, 'ip-ttl-propagate': 1, 'default-ttl': 255},
        'frr': {'global': []}}


def test_nested_ldp_adapter_preserves_other_protocols():
    original = 'interface dum1\n ip ospf cost 10\nexit\nmpls ldp\n address-family ipv4\n  interface dum1\n  exit\n exit-address-family\nexit\nrouter bgp 65000\nexit\n'
    desired = frr_ldp.adapter.desired('mpls ldp\n router-id 192.0.2.1\n address-family ipv6\n  interface dum2\n   discovery hello interval 3\n  exit\n exit-address-family\nexit\n')
    result = frr_ldp.adapter.replace(original, desired)
    assert 'router bgp 65000' in result
    assert 'ip ospf cost 10' in result
    assert 'address-family ipv4' not in result
    assert frr_ldp.adapter.select(result, desired) == desired
    removed = frr_ldp.adapter.replace(result, {'mpls ldp': []})
    assert 'mpls ldp' not in removed
    assert 'interface dum1' in removed


@pytest.mark.parametrize('settings,mpls_settings,match', [
    ({}, None, 'requires protocols mpls'),
    ({'neighbor': {'192.0.2.2': {'ttl-security': {'disable': {}, 'hops': '2'}}}}, {}, 'mutually exclusive'),
    ({'address-family': {'ipv4': {'interface': {'dum1': {}}}}}, {}, 'enable it'),
    ({'address-family': {'ipv4': {'label': {'local': {'allocate': {'host-routes': {}, 'access-list': 'ACL'}}}}}}, {}, 'mutually exclusive'),
])
def test_ldp_relational_validation(settings, mpls_settings, match):
    with pytest.raises(ValidationError, match=match):
        protocols_ldp.verify({'ldp': settings, 'mpls': mpls_settings, 'interfaces': {},
                              'policies': {'access-list': {'ipv4': {'ACL': {}}}}}, None)


def test_ipv6_peer_filters_use_ipv4_lsr_ids():
    settings = {'address-family': {'ipv6': {'label': {'remote': {'accept': {
        'from-access-list': 'PEERS', 'for-access-list': 'PREFIXES'}}}}}}
    configuration = {'ldp': settings, 'mpls': {}, 'interfaces': {},
                     'policies': {'access-list': {'ipv4': {'PEERS': {}}, 'ipv6': {'PREFIXES': {}}}}}
    protocols_ldp.verify(configuration, None)
    configuration['policies']['access-list']['ipv4'].clear()
    with pytest.raises(ValidationError, match='ipv4 access-list'):
        protocols_ldp.verify(configuration, None)


@pytest.fixture
def sysctls(tmp_path, monkeypatch):
    monkeypatch.setattr(mpls, 'ROOT', tmp_path)
    (tmp_path / 'platform_labels').write_text('0')
    (tmp_path / 'ip_ttl_propagate').write_text('1')
    (tmp_path / 'default_ttl').write_text('255')
    for name in ('dum1', 'dum2'):
        path = tmp_path / 'conf' / name
        path.mkdir(parents=True)
        (path / 'input').write_text('0')
    return tmp_path


def test_enable_remove_and_recreated_link(sysctls, tmp_path):
    manager = Manager(Kernel(), None, directory=tmp_path / 'journal', boot='test')
    desired = {'interfaces': ['dum1'], 'label-table-size': 1048575}
    manager.replace_mpls(desired)
    assert (sysctls / 'platform_labels').read_text() == '1048575'
    assert (sysctls / 'conf/dum1/input').read_text() == '1'
    assert (sysctls / 'conf/dum2/input').read_text() == '0'
    (sysctls / 'conf/dum1/input').write_text('0')
    assert 'dum1' in manager.affected([Message(event='RTM_NEWLINK', index=99, IFLA_IFNAME='dum1')])
    manager.reconcile_mpls()
    assert (sysctls / 'conf/dum1/input').read_text() == '1'
    manager.replace_mpls({'interfaces': [], 'label-table-size': 1048575})
    assert (sysctls / 'conf/dum1/input').read_text() == '0'


def test_interface_creation_applies_pending_mpls_before_return(sysctls, tmp_path, monkeypatch):
    kernel = Kernel()
    manager = Manager(kernel, Leases(), directory=tmp_path / 'journal', boot='test')
    manager.replace_mpls({'interfaces': ['dum3'], 'label-table-size': 1024})
    original = kernel.add

    def create(name, kind=''):
        original(name, kind)
        path = sysctls / 'conf' / name
        path.mkdir()
        (path / 'input').write_text('0')

    monkeypatch.setattr(kernel, 'add', create)
    manager.replace('dummy', {'dum3': {'kind': 'dummy'}})
    assert (sysctls / 'conf/dum3/input').read_text() == '1'


def test_failed_mpls_apply_restores_previous(sysctls, tmp_path, monkeypatch):
    manager = Manager(Kernel(), None, directory=tmp_path / 'journal', boot='test')
    old = {'interfaces': ['dum1'], 'label-table-size': 1048575}
    manager.replace_mpls(old)
    original = mpls.write

    def fail_second(path, value):
        if path == sysctls / 'conf/dum2/input' and value == 1:
            raise OSError('injected write failure')
        original(path, value)

    monkeypatch.setattr(mpls, 'write', fail_second)
    with pytest.raises(RouterError, match='previous settings restored'):
        manager.replace_mpls({'interfaces': ['dum2'], 'label-table-size': 1024})
    assert manager.state['mpls'] == old
    assert (sysctls / 'conf/dum1/input').read_text() == '1'
    assert 'mpls-pending' not in manager.state


def test_interrupted_mpls_change_restores_before_image(sysctls, tmp_path):
    manager = Manager(Kernel(), None, directory=tmp_path / 'journal', boot='test')
    before = {'interfaces': ['dum1'], 'label-table-size': 1024}
    target = {'interfaces': ['dum2'], 'label-table-size': 2048}
    manager.state['mpls-pending'] = {'before': before, 'target': target}
    manager.save()
    mpls.apply(target)
    restored = Manager(Kernel(), None, directory=tmp_path / 'journal', boot='test')
    restored.reconcile_mpls()
    assert restored.state['mpls'] == before
    assert (sysctls / 'conf/dum1/input').read_text() == '1'
    assert (sysctls / 'conf/dum2/input').read_text() == '0'


@pytest.mark.parametrize('line', ['show mpls status', 'show mpls table 100 json',
    'show mpls ldp ipv6 discovery detail json', 'show mpls ldp neighbor 192.0.2.1 capabilities',
    'clear mpls ldp neighbor', 'clear mpls ldp neighbor 2001:db8::2'])
def test_operational_commands_pass_native_tokens(line, monkeypatch):
    operation = line.split()[0]
    monkeypatch.setattr(operational.vtysh, operation, lambda words: list(words))
    assert getattr(operational, operation)(line) == line.split()
