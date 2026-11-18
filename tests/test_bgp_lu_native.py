"""LU family changes, peer inheritance and native FRR readback in isolation.

One namespace and stable FRR processes cover the complete module. No adjacency
waits or packet probes: labeled forwarding belongs to the shared routed suite.
"""

from contextlib import ExitStack
from copy import deepcopy
import os
from pathlib import Path
import subprocess
import time

import pytest

from nvyr.config_scripts import protocols_bgp as bgp
from nvyr.helpers import frr_bgp
from nvyr.helpers.frr_reload import Manager


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_LU_NATIVE') != '1', reason='requires disposable FRR')


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.fixture(scope='module')
def native(tmp_path_factory):
    state = tmp_path_factory.mktemp('lu-native')
    # Imported by several modules in one pytest process; each module owns its lab.
    namespace = f'nvyr-lu-native-{os.getpid()}-{state.name}'
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
        for daemon in ('mgmtd', 'zebra', 'bgpd', 'staticd', 'ldpd'):
            config = directory / (daemon + '.conf')
            startup = Path(__file__).resolve().parents[1] / 'packaging/frr-zebra.conf'
            config.write_text(startup.read_text() if daemon == 'zebra' else '')
            arguments = ['ip', 'netns', 'exec', namespace, '/usr/lib/frr/' + daemon,
                         '-N', namespace, '-z', str(directory / 'zserv.api'),
                         '--vty_socket', str(directory), '-i', str(directory / (daemon + '.pid')), '-P', '0']
            if daemon not in ('mgmtd', 'staticd'):
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
        manager = Manager(runner=runner, directory=directory)
        yield manager, state


def apply(native, configuration):
    manager, state = native
    desired = bgp.generate({'instances': configuration}, None)
    manager.apply('bgp', desired, state, adapter=frr_bgp.adapter, daemons=('zebra', 'bgpd'))
    assert frr_bgp.adapter.select(manager.snapshot(), desired) == desired


@pytest.mark.parametrize('explicit_null', ['ipv4', 'ipv6', 'both'])
def test_family_settings_and_removal(native, explicit_null):
    instance = {'local-as': '65000', 'parameters': {'labeled-unicast': {'explicit-null': explicit_null}},
                'address-family': {'ipv4-labeled-unicast': {'maximum-paths': {'ebgp': '4', 'ibgp': '2'}},
                                   'ipv6-labeled-unicast': {'maximum-paths': {'ebgp': '2', 'ibgp': '4'},
                                                            'next-hop': {'prefer-global': {}}}},
                'neighbor': {'192.0.2.2': {'remote-as': '65001', 'shutdown': {}, 'address-family': {
                    'ipv4-labeled-unicast': {}, 'ipv6-labeled-unicast': {}}}}}
    apply(native, {'default': instance})
    instance.pop('parameters')
    instance.pop('address-family')
    apply(native, {'default': instance})
    apply(native, {})


@pytest.mark.parametrize('family', ['ipv4-labeled-unicast', 'ipv6-labeled-unicast'])
@pytest.mark.parametrize('settings', [
    {'next-hop-self': {'force': {}}, 'soft-reconfiguration': {'inbound': {}},
     'maximum-prefix': {'limit': '200', 'threshold': '90', 'force': {}, 'warning-only': {}},
     'maximum-prefix-out': '300', 'weight': '75'},
    {'addpath': {'transmit': {'best-selected': '2'}, 'receive-limit': '4'}, 'send-community': ['standard']},
    {'as-override': {}, 'allowas-in': {'count': '2'}, 'remove-private-as': {'all': {'replace': {}}}},
    {'attribute-unchanged': {'as-path': {}, 'next-hop': {}, 'med': {}}, 'default-originate': {}},
])
def test_peer_options_and_group_inheritance(native, family, settings):
    instance = {'local-as': '65000', 'peer-group': {'LU': {'remote-as': '65001', 'address-family': {family: deepcopy(settings)}}},
                'neighbor': {'192.0.2.2': {'peer-group': 'LU', 'shutdown': {}}}}
    apply(native, {'default': instance})
    instance['neighbor']['192.0.2.2']['address-family'] = {family: {'disable': {}}}
    apply(native, {'default': instance})
    apply(native, {})


@pytest.mark.parametrize('family', ['ipv4-labeled-unicast', 'ipv6-labeled-unicast'])
def test_neighbor_addpath_receive_limit(native, family):
    instance = {'local-as': '65000', 'neighbor': {'192.0.2.2': {
        'remote-as': '65001', 'shutdown': {}, 'address-family': {family: {
            'addpath': {'receive-limit': '4', 'transmit': {'all': {}}}}}}}}
    apply(native, {'default': instance})
    apply(native, {})


@pytest.mark.parametrize('family', ['ipv4-unicast', 'ipv6-unicast', 'ipv4-labeled-unicast', 'ipv6-labeled-unicast'])
def test_group_receive_limit_changes_and_member_override(native, family):
    group = {'remote-as': '65001', 'address-family': {family: {'addpath': {'receive-limit': '4'}}}}
    instance = {'local-as': '65000', 'peer-group': {'LU': group}}
    apply(native, {'default': instance})
    instance['neighbor'] = {'192.0.2.2': {'peer-group': 'LU', 'shutdown': {}}}
    apply(native, {'default': instance})
    instance['neighbor']['192.0.2.2']['address-family'] = {family: {'addpath': {'receive-limit': '7'}}}
    apply(native, {'default': instance})
    group['address-family'][family]['addpath']['receive-limit'] = '9'
    apply(native, {'default': instance})
    del instance['neighbor']['192.0.2.2']['address-family']
    apply(native, {'default': instance})
    del group['address-family'][family]['addpath']
    apply(native, {'default': instance})
    apply(native, {})
