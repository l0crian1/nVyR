"""The combined saved configuration must pass actual schema and lifecycle validation."""

from copy import deepcopy
from ipaddress import ip_address
import json

from acceptance import baseline
from nvyr.engine import Engine
from nvyr.helpers import interfaces, kea, nftables
from nvyr.helpers.kernel_settings_map import INTERFACE_SETTINGS
from nvyr.helpers.nftables_timeouts import STATES
from nvyr.tree import lookup, MISSING
from tests.lifecycle import recorded_registry


OPTIONS = {'ethernet': 'eth1', 'image': 'alpine', 'assets': 'boot-00000000-0000-0000-0000-000000000001'}


def test_comprehensive_configuration_and_restore(controller, engine, session, monkeypatch, tmp_path):
    """Exercise every literal CLI line and real verify/generate functions in one commit."""
    monkeypatch.setattr(interfaces, 'local_addresses', lambda **kwargs: {
        ip_address('198.18.196.1'), ip_address('2001:db8:196::1'),
    } if kwargs.get('vrf') == 'BOOTLEFT' else set())
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    devices = {
        'dum995': {'vrf': 'default', 'addresses': ['198.18.195.1', '2001:db8:195::1', 'fe80::195'], 'up': True, 'running': True},
        'veth993': {'vrf': 'BOOTLEFT', 'addresses': ['198.18.193.1', '2001:db8:193::1', 'fe80::193'], 'up': True, 'running': True},
    }
    monkeypatch.setattr(kea, 'inventory', lambda: devices)
    rendered = []
    monkeypatch.setattr(nftables.manager, 'apply', lambda text, *args, **kwargs: rendered.append(text))

    # Preserve management addressing and restore the spare port's original disabled state.
    controller.execute('set interfaces ethernet eth0 address 10.0.101.28/24', session)
    controller.execute('set interfaces ethernet eth1 disable description "Spare port"', session)
    controller.execute('set system ntp server 192.0.2.123 prefer', session)
    initial = engine.commit(session)
    assert all(unit['success'] for unit in initial['results'].values())
    original = deepcopy(engine.running)

    class Config:
        def get_config(self):
            return deepcopy(engine.running)

        def set(self, command):
            return controller.execute(command, session)

        def delete(self, command):
            return controller.execute(command, session)

    baseline.configure(Config(), OPTIONS)
    # Report verification failures before partial-commit compensation obscures them.
    checked = engine.check(session)
    assert all(unit['success'] for unit in checked['results'].values()), checked
    result = engine.commit(session)
    failures = {name: unit for name, unit in result['results'].items() if not unit['success']}
    assert failures == {}
    firewall = next(text for text in reversed(rendered) if '\ntable inet nvyr_filter {' in text)
    (tmp_path / 'firewall.nft').write_text(firewall)
    (tmp_path / 'configuration.json').write_text(json.dumps(engine.running))

    # Aardvark must forward to an upstream resolver, never its own bridge gateway.
    containers = engine.running['container']
    gateways = {
        subnet['gateway']
        for network in containers['network'].values()
        for subnet in network['subnet'].values()
        if 'disable-dns' not in network
    }
    resolvers = containers['name']['BOOTBOX']['name-server']
    assert resolvers == ['1.1.1.1']
    assert not gateways.intersection(resolvers)

    # Native output must retain prefixes, flattened inclusions and numeric NFLOG arguments.
    assert 'devices = { "veth995*", "veth997*" }' in firewall
    assert 'iifname { "dum995*" }' in firewall
    assert '198.18.196.0/24' in firewall
    assert '2001:db8:196::/64' in firewall
    assert 'log prefix "[ipv4-OUT-filter-41980-A]" group ' in firewall
    assert 'log prefix "[ipv6-OUT-filter-41980-A]" group ' in firewall
    assert 'group $' not in firewall

    # Every per-interface setting must have an explicit recovery exercise somewhere.
    covered = set()
    for _, settings in interfaces.configured(engine.running):
        covered.update(path for path in INTERFACE_SETTINGS if lookup(settings, path, MISSING) is not MISSING)
    assert set(INTERFACE_SETTINGS) - covered == set()

    # TCP states and both UDP states must not disappear from the combined fixture.
    groups = engine.running['firewall']['group']
    assert set(groups['timeout-group']['ipv4']['BOOTTCP']['timeout']) == set(STATES['tcp'])
    assert set(groups['timeout-group']['inet']['BOOTUDP']['timeout']) == set(STATES['udp'])
    for family in ('inet', 'ipv4', 'ipv6'):
        assert {'ingress', 'input', 'output', 'forward', 'prerouting'} <= engine.running['firewall'][family].keys()
    assert engine.running['firewall']['flowtable']['BOOTFAST']['counter'] is True
    assert 'time.boot.example.invalid' in engine.running['system']['ntp']['server']
    assert '192.0.2.123' not in engine.running['system']['ntp']['server']

    assert set(result['results']) >= {'firewall', 'firewall_failsafe', 'static', 'bgp', 'policy', 'container',
                                      'dhcp-server', 'dhcpv6-server', 'bridge', 'ethernet',
                                      'dummy', 'virtual-ethernet', 'loopback', 'vrf', 'vrf_conntrack', 'ntp'}

    # Replay every owner from saved configuration with a new kernel boot identity.
    engine.save(session)
    restarted_modules = recorded_registry(engine.schema)
    # Reboot must retain the fixture's container generation double: this unit
    # test does not provision /config volume assets on the development machine.
    restarted_modules['container'].generate = engine.modules['container'].generate
    restarted = Engine(engine.schema, restarted_modules, engine.store, boot_id='acceptance-cold-boot')
    assert not restarted.unhealthy
    assert restarted.running == engine.running

    controller.load(session, json.dumps(original), replace=True)
    result = engine.commit(session)
    failures = {name: unit for name, unit in result['results'].items() if not unit['success']}
    assert failures == {}
    assert engine.running == original
