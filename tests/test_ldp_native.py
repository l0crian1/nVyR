"""LDP native configuration/readback, defaults and reload removal.

Uses one stable interface pair and private FRR processes in a network namespace.
No packet or adjacency assertions belong here; existing host FRR is untouched.
"""

from contextlib import ExitStack
from copy import deepcopy
import os
from pathlib import Path
import subprocess
import time

import pytest

from nvyr.config_scripts import protocols_ldp, protocols_ospf, protocols_isis
from nvyr.helpers import frr_ldp, frr_ospf, frr_isis
from nvyr.helpers.frr_reload import Manager

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_LDP_NATIVE') != '1', reason='requires disposable FRR')


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout


@pytest.fixture(scope='module')
def native(tmp_path_factory):
    state = tmp_path_factory.mktemp('ldp-native')
    namespace = f'nvyr-ldp-native-{os.getpid()}'
    directory = Path('/tmp') / namespace
    directory.mkdir()
    run('chown', 'frr:frr', str(directory))

    def runner(argv):
        if argv[0] == 'vtysh':
            argv = [argv[0], '--vty_socket', str(directory), *argv[1:]]
        elif argv[0].endswith('frr-reload.py'):
            argv = [*argv, '--vty_socket', str(directory)]
        return run('ip', 'netns', 'exec', namespace, *argv)

    with ExitStack() as cleanup:
        run('ip', 'netns', 'add', namespace)
        cleanup.callback(run, 'ip', 'netns', 'del', namespace)
        run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
        run('ip', '-n', namespace, 'link', 'add', 'ldpnative0', 'type', 'veth', 'peer', 'name', 'ldpnative1')
        run('ip', '-n', namespace, 'link', 'set', 'ldpnative0', 'up')
        run('ip', '-n', namespace, 'link', 'set', 'ldpnative1', 'up')
        for daemon in ('mgmtd', 'zebra', 'ldpd', 'ospfd', 'isisd'):
            config = directory / (daemon + '.conf')
            config.write_text('')
            arguments = ['ip', 'netns', 'exec', namespace, '/usr/lib/frr/' + daemon,
                         '-N', namespace, '-u', 'frr', '-g', 'frr', '-z', str(directory / 'zserv.api'),
                         '--vty_socket', str(directory), '-i', str(directory / (daemon + '.pid')), '-P', '0']
            if daemon != 'mgmtd':
                arguments.extend(['-f', str(config)])
            log = cleanup.enter_context((directory / (daemon + '.log')).open('w'))
            process = subprocess.Popen(arguments, stdout=log, stderr=log)
            cleanup.callback(process.wait, timeout=10)
            cleanup.callback(process.terminate)
            deadline = time.monotonic() + 10
            while not (directory / (daemon + '.vty')).exists():
                assert process.poll() is None, (directory / (daemon + '.log')).read_text()
                assert time.monotonic() < deadline, 'FRR socket did not appear'
                time.sleep(.1)
        manager = Manager(runner=runner, directory=directory,
                          executable=os.environ.get('NVYR_LDP_RELOAD', '/usr/lib/frr/frr-reload.py'))
        yield manager, state


def apply(native, extra=None, family=None):
    manager, state = native
    settings = {'options': {'router-id': '192.0.2.90'}, **deepcopy(extra or {})}
    settings['address-family'] = {
        'ipv4': {'transport-address': '192.0.2.90', 'interface': {'ldpnative0': {}}, **deepcopy(family or {})},
        'ipv6': {'transport-address': '2001:db8::90', 'interface': {'ldpnative0': {}}, **deepcopy(family or {})}}
    desired = protocols_ldp.generate({'ldp': settings}, None)
    manager.apply('ldp', desired, state, adapter=frr_ldp.adapter, daemons=('zebra', 'ldpd'))
    assert frr_ldp.adapter.select(manager.snapshot(), desired) == desired


@pytest.mark.parametrize('extra', [
    {},
    {'options': {'router-id': '192.0.2.91', 'ordered-control': {}, 'wait-for-sync': '20', 'allow-broken-lsps': {}}},
    {'options': {'dual-stack': {'transport-preference': 'ipv4', 'cisco-interop': {}}}},
    {'options': {'dual-stack': {'transport-preference': 'ipv6'}}},
    {'discovery': {'hello': {'interval': '3', 'holdtime': '12'}, 'targeted-hello': {'interval': '7', 'holdtime': '30'}}},
    {'discovery': {'hello': {'interval': '5', 'holdtime': '15'}, 'targeted-hello': {'interval': '5', 'holdtime': '45'}}},
    {'neighbor': {'192.0.2.92': {'password': 'native-md5', 'session-holdtime': '30', 'ttl-security': {'hops': '3'}}}},
    {'neighbor': {'192.0.2.92': {'ttl-security': {'disable': {}}}}},
])
def test_global_settings(native, extra):
    apply(native, extra=extra)
    apply(native)


@pytest.mark.parametrize('family', [
    {'session-holdtime': '30', 'ttl-security': {'disable': {}}},
    {'session-holdtime': '180'},
    {'discovery': {'hello': {'interval': '4', 'holdtime': '20'}, 'targeted-hello': {'interval': '8', 'holdtime': '40', 'accept': {}}}},
    {'label': {'local': {'allocate': {'host-routes': {}}, 'advertise': {'explicit-null': {}}}}},
    {'label': {'local': {'allocate': {'access-list': 'NATIVE'}, 'advertise': {'to-access-list': 'PEERS', 'for-access-list': 'NATIVE', 'explicit-null': {'for-access-list': 'NATIVE'}}},
               'remote': {'accept': {'from-access-list': 'PEERS', 'for-access-list': 'NATIVE'}}}},
    {'interface': {'ldpnative0': {'hello': {'interval': '2', 'holdtime': '10'}, 'disable-establish-hello': {}}}},
    {'interface': {'ldpnative0': {'hello': {'interval': '5', 'holdtime': '15'}}}},
])
def test_family_settings(native, family):
    apply(native, family=family)
    apply(native)


def test_delete_recreate(native):
    manager, state = native
    apply(native)
    manager.apply('ldp', {}, state, adapter=frr_ldp.adapter)
    assert 'mpls ldp' not in manager.snapshot().splitlines()
    apply(native)


def test_explicit_native_timer_defaults_override_process(native):
    apply(native, extra={'discovery': {'hello': {'interval': '3', 'holdtime': '12'},
                                     'targeted-hello': {'interval': '7', 'holdtime': '30'}}},
          family={'discovery': {'hello': {'interval': '5', 'holdtime': '15'},
                                'targeted-hello': {'interval': '5', 'holdtime': '45'}},
                  'interface': {'ldpnative0': {'hello': {'interval': '5', 'holdtime': '15'}}}})
    snapshot = native[0].snapshot()
    assert '   discovery hello interval 5' in snapshot
    assert '  discovery hello holdtime 15' in snapshot
    assert '  discovery targeted-hello interval 5' in snapshot
    assert '  discovery targeted-hello holdtime 45' in snapshot
    apply(native)


@pytest.mark.parametrize('protocol', ['ospf', 'isis'])
@pytest.mark.parametrize('interface', [{}, {'hold-down': '12'}, {'disable': {}}, {'hold-down': '0'}])
def test_igp_synchronization(native, protocol, interface):
    manager, state = native
    module = protocols_ospf if protocol == 'ospf' else protocols_isis
    adapter = frr_ospf.ipv4 if protocol == 'ospf' else frr_isis.adapter
    settings = {'ldp-sync': {'hold-down': '20'}}
    circuit = {'ldp-sync': deepcopy(interface)}
    if protocol == 'isis':
        settings['net'] = ['49.0001.0000.0000.0090.00']
        circuit['address-family'] = ['ipv4-unicast']
    else:
        circuit['area'] = '0'
    settings['interface'] = {'ldpnative0': circuit}
    desired = module.generate({'instances': {'default': settings}}, None)
    manager.apply(protocol, desired, state, adapter=adapter)
    assert adapter.select(manager.snapshot(), desired) == desired
    # An interface override must survive changing the process's inherited timer.
    settings['ldp-sync']['hold-down'] = '25'
    desired = module.generate({'instances': {'default': settings}}, None)
    manager.apply(protocol, desired, state, adapter=adapter)
    assert adapter.select(manager.snapshot(), desired) == desired
    # Toggling process synchronization must retain an explicit interface choice.
    process_sync = settings.pop('ldp-sync')
    desired = module.generate({'instances': {'default': settings}}, None)
    manager.apply(protocol, desired, state, adapter=adapter)
    assert adapter.select(manager.snapshot(), desired) == desired
    settings['ldp-sync'] = process_sync
    desired = module.generate({'instances': {'default': settings}}, None)
    manager.apply(protocol, desired, state, adapter=adapter)
    assert adapter.select(manager.snapshot(), desired) == desired
    circuit.pop('ldp-sync')
    desired = module.generate({'instances': {'default': settings}}, None)
    manager.apply(protocol, desired, state, adapter=adapter)
    assert adapter.select(manager.snapshot(), desired) == desired
    settings.pop('ldp-sync')
    desired = module.generate({'instances': {'default': settings}}, None)
    manager.apply(protocol, desired, state, adapter=adapter)
