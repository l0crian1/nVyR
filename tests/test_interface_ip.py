"""Shared IP schema, inheritance, address derivation and native write ordering."""

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from nvyr.errors import ValidationError, RouterError
from nvyr.helpers import interface_ip, interfaces, kernel_settings
from nvyr.helpers.kernel_settings_map import INTERFACE_SETTINGS, SETTINGS, ARP_IGNORE_CHOICES
from nvyr.helpers.netlink import normalize


@pytest.mark.parametrize('path', [
    'ethernet eth1', 'ethernet eth1 vif 10', 'dummy dum1',
    'virtual-ethernet veth1', 'virtual-ethernet veth1 vif 10',
    'bridge br1', 'bridge br1 vif 10',
])
def test_shared_arp_ignore_choices(controller, session, path):
    controller.execute(f'set interfaces {path} ip arp-ignore 2', session)
    result = controller.completion(f'set interfaces {path} ip arp-ignore ', session, explicit=True)
    text = str(result)
    for description in ARP_IGNORE_CHOICES.values():
        assert description in text


def test_options_reach_daemon_and_do_not_install_override_defaults(controller, engine, session, monkeypatch):
    calls = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda owner, links, **kwargs: calls.append(links))
    controller.execute('set interfaces dummy dum1 ip arp-ignore 2 arp-cache-timeout 2m', session)
    controller.execute('set interfaces dummy dum1 ipv6 autoconf no-default-route', session)
    result = engine.commit(session)
    assert result['results']['dummy']['success']
    assert calls[-1]['dum1']['ip-options'] == {
        'ip': {'arp-ignore': '2', 'arp-cache-timeout': '2m'},
        'ipv6': {'autoconf': True, 'no-default-route': True},
    }

    controller.execute('delete interfaces dummy dum1 ip', session)
    assert engine.commit(session)['results']['dummy']['success']
    assert 'ip' not in calls[-1]['dum1']['ip-options']


def test_invalid_arp_ignore_modes_are_rejected(controller, session):
    with pytest.raises(RouterError):
        controller.execute('set interfaces dummy dum1 ip arp-ignore 4', session)


@pytest.mark.parametrize('options, addresses, message', [
    ({'ipv6': {'disable': True}}, ['2001:db8::1/64'], 'conflicts'),
    ({'ipv6': {'disable': True, 'autoconf': True}}, [], 'conflicts'),
    ({'ipv6': {'no-default-route': True}}, [], 'require'),
    ({'ipv6': {'no-ra-mtu': True}}, [], 'require'),
    ({'ipv6': {'interface-identifier': '::1234'}}, [], 'require'),
    ({'ipv6': {'temporary-addresses': 'prefer-temporary'}}, [], 'require'),
    ({'ipv6': {'autoconf': True, 'interface-identifier': '::1', 'address-generation': 'stable-privacy'}}, [], 'conflicts'),
    ({'ipv6': {'address-generation': 'stable-privacy', 'no-default-link-local': True}}, [], 'requires'),
    ({'ipv6': {'duplicate-address-detection': {'disable': True, 'probes': '2'}}}, [], 'conflicts'),
    ({'ip': {'arp-ignore': '4'}}, [], 'invalid'),
    ({'ip': {'arp-cache-timeout': '0s'}}, [], 'invalid'),
    ({'ipv6': {'eui64': ['2001:db8::1/64']}}, [], 'invalid'),
    ({'ipv6': {'eui64': ['2001:db8::/48']}}, [], 'invalid'),
    ({'ipv6': {'link-local-address': '2001:db8::1'}}, [], 'invalid'),
    ({'ipv6': {'autoconf': True, 'interface-identifier': '2001:db8::1'}}, [], 'invalid'),
])
def test_invalid_combinations(options, addresses, message):
    with pytest.raises(ValidationError, match=message):
        interface_ip.normalize(options, addresses=addresses)


def test_daemon_enforces_applicability_and_checks_values():
    with pytest.raises(ValidationError, match='not supported'):
        normalize({'lo': {'kind': 'loopback', 'ip-options': {'ip': {'arp-ignore': '2'}}}})
    with pytest.raises(ValidationError, match='unknown'):
        interface_ip.normalize({'ip': {'bogus': '1'}})


def test_global_inheritance_override_and_removal():
    globals = {'ipv4 arp ignore': '1', 'ipv6 receive-redirects': 'enable'}
    assert interface_ip.effective({}, globals)['ipv4 arp ignore'] == '1'
    values = interface_ip.effective({'ip': {'arp-ignore': '2'}}, globals)
    assert values['ipv4 arp ignore'] == '2'
    assert values['ipv6 receive-redirects'] == 'enable'
    assert interface_ip.effective({}, globals)['ipv4 arp ignore'] == '1'


def test_eui64_uses_actual_mac_and_supports_multiple_prefixes():
    options = {'ipv6': {'eui64': ['2001:db8:1::/64', '2001:db8:2::/64'], 'link-local-address': 'fe80::1234'}}
    assert interface_ip.addresses(options, '02:00:00:12:34:56') == [
        '2001:db8:1::ff:fe12:3456/64', '2001:db8:2::ff:fe12:3456/64', 'fe80::1234/64']


def test_stable_secret_survives_restart_and_is_per_interface(tmp_path):
    first = interface_ip.Controller(secret=tmp_path / 'secret.json')
    secret = first.stable_secret('eth1')
    assert secret != first.stable_secret('eth2')
    assert interface_ip.Controller(secret=tmp_path / 'secret.json').stable_secret('eth1') == secret
    assert first.secret.stat().st_mode & 0o777 == 0o600


def test_global_rpc_restores_settings_after_firewall_failure(monkeypatch):
    calls = []

    def request(operation, **arguments):
        calls.append((operation, arguments))
        return {'previous': {'ipv4 arp ignore': '1'}}

    monkeypatch.setattr(interfaces.manager, 'request', request)
    with pytest.raises(RuntimeError, match='nft failure'):
        with kernel_settings.RemoteManager().transaction({'ipv4 arp ignore': '2'}):
            raise RuntimeError('nft failure')
    assert calls == [
        ('replace-kernel-settings', {'values': {'ipv4 arp ignore': '2'}}),
        ('replace-kernel-settings', {'values': {'ipv4 arp ignore': '1'}}),
    ]


def test_native_policy_order_and_presence_conversion(tmp_path):
    settings = kernel_settings.Manager(tmp_path / 'proc')
    for name in INTERFACE_SETTINGS.values():
        path = settings.path(name, interface='eth1')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('0\n')
    events = []
    kernel = SimpleNamespace(refresh_addresses=lambda: events.append('refresh'),
                             ipv6_token=lambda name, token: events.append(('token', token)),
                             ipv6_ra_routes=lambda name, **kwargs: events.append('routes'))
    controller = interface_ip.Controller(settings, tmp_path / 'secret.json')
    controller.apply(kernel, 'eth1', {'ip': {'disable-forwarding': True}, 'ipv6': {
        'autoconf': True, 'no-default-route': True, 'interface-identifier': '::1234'}}, {})
    assert settings.path('interface ip disable-forwarding', interface='eth1').read_text().strip() == '0'
    assert settings.path('interface ipv6 accept-router-advertisements', interface='eth1').read_text().strip() == '2'
    assert settings.path('interface ipv6 no-default-route', interface='eth1').read_text().strip() == '0'
    assert events[-1] == ('token', '::1234')

    controller.apply(kernel, 'eth1', {}, {'ipv4 arp ignore': '8'})
    assert settings.path('ipv4 arp ignore', interface='eth1').read_text().strip() == '8'
    assert settings.path('interface ip disable-forwarding', interface='eth1').read_text().strip() == '1'
    assert settings.path('interface ipv6 accept-router-advertisements', interface='eth1').read_text().strip() == '0'


def test_runtime_profile_prevents_late_udev_overwrite_and_rolls_back(tmp_path):
    settings = kernel_settings.Manager(tmp_path / 'proc')
    controller = interface_ip.Controller(settings, profile=tmp_path / '95-interfaces.conf')
    owners = {'ethernet': {'eth1.10': {'kind': 'vlan', 'ip-options': {'ip': {'arp-ignore': '2'}}}}}
    with controller.profile_transaction(owners, {'ipv4 arp ignore': '1'}):
        assert 'net/ipv4/conf/eth1.10/arp_ignore = 2\n' in controller.profile.read_text()
        assert 'net/ipv6/conf/eth1.10/accept_ra = 0\n' in controller.profile.read_text()
    before = controller.profile.read_text()

    with pytest.raises(RuntimeError):
        with controller.profile_transaction({}, {}):
            assert 'eth1.10' not in controller.profile.read_text()
            raise RuntimeError('failed link update')
    assert controller.profile.read_text() == before

    owners['ethernet']['eth1.10']['ip-options'] = {}
    with controller.profile_transaction(owners, {'ipv4 arp ignore': '1'}):
        assert 'net/ipv4/conf/eth1.10/arp_ignore = 1\n' in controller.profile.read_text()


def test_global_daemon_transaction_retains_interface_overrides(tmp_path, monkeypatch):
    from nvyr.helpers.link_manager import Manager
    from tests.test_netlink import Kernel, Leases

    manager = Manager(Kernel(), Leases(), tmp_path / 'state')
    manager.replace('dummy', {'dum1': {'kind': 'dummy', 'ip-options': {'ip': {'arp-ignore': '2'}}}})
    calls = []

    @contextmanager
    def transaction(values, **kwargs):
        calls.append((values, kwargs))
        yield

    monkeypatch.setattr(kernel_settings, 'Manager', lambda: SimpleNamespace(transaction=transaction))
    values = kernel_settings.firewall_values({}) | {'ipv4 arp ignore': '1'}
    result = manager.replace_kernel_settings(values)
    assert result['previous']['ipv4 arp ignore'] == '0'
    assert calls[0][1] == {'overrides': {'dum1': {'ipv4 arp ignore': '2'}}, 'profile_overrides': False}
    assert manager.state['kernel-settings']['ipv4 arp ignore'] == '1'

    restored = Manager(manager.kernel, Leases(), tmp_path / 'state')
    assert restored.state['kernel-settings'] == values


def test_netlink_sandbox_waits_for_kernel_setting_paths():
    unit = (Path(__file__).resolve().parents[1] / 'packaging/nvyr-netlinkd.service').read_text()
    fields = dict(line.split('=', 1) for line in unit.splitlines() if '=' in line and not line.startswith('#'))
    assert 'nvyr-conntrack.service' in fields['Requires'].split()
    assert 'nvyr-conntrack.service' in fields['After'].split()
    assert 'ReadWritePaths=/proc/sys/net/ipv4 /proc/sys/net/ipv6 /proc/sys/net/netfilter' in unit
