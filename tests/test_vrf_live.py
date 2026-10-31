"""Opt-in VRF kernel tests in a disposable container, never on the router host."""

import os
from copy import deepcopy

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.netlink import Kernel, TYPES, read_attributes
from tests.test_netlink_live import daemon, isolated, run, wait_for

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETLINK_TEST') != '1',
                                reason='requires isolated privileged Netlink container')


def test_real_vrf_create_recover_restart_reject_change_and_delete(daemon):
    client, process, restart = daemon
    kernel = Kernel()
    links = {'BLUE': {'kind': 'vrf', 'attributes': {'table': 100}},
             'RED': {'kind': 'vrf', 'attributes': {'table': 4294967295}}}

    def ready(name):
        device = kernel.device(name)
        return (device is not None and device['kind'] == 'vrf' and device['up']
                and read_attributes(device['message'], TYPES['vrf'].keymap) == links[name]['attributes'])

    try:
        client.replace('vrf', links)
        assert ready('BLUE') and ready('RED')

        run('ip', 'link', 'set', 'BLUE', 'down')
        wait_for(lambda: ready('BLUE'))
        run('ip', 'link', 'del', 'BLUE')
        wait_for(lambda: ready('BLUE'))

        process.terminate()
        process.wait(timeout=10)
        run('ip', 'link', 'del', 'BLUE')
        restart()
        wait_for(lambda: ready('BLUE'))
        assert ready('RED')

        with pytest.raises(RouterError, match='table cannot be changed'):
            client.replace('vrf', dict(links, BLUE={'kind': 'vrf', 'attributes': {'table': 101}}))

        assert ready('BLUE') and ready('RED')

        client.replace('vrf', {})
        assert kernel.device('BLUE') is None and kernel.device('RED') is None
    finally:
        client.replace('vrf', {}, recovery=True)
        kernel.close()


def test_real_vrf_member_move_drift_recreation_restart_and_removal(daemon):
    client, process, restart = daemon
    kernel = Kernel()
    links = {'dum98': {'kind': 'dummy', 'attributes': {'vrf': 'BLUE', 'link-group': 4294967295},
                       'addresses': ['192.0.2.98/24', '2001:db8::98/64']}}

    def member(vrf, group):
        device = kernel.device('dum98')
        master = kernel.device(vrf) if vrf else None
        return (device is not None and device['attributes']['vrf'] == (master['index'] if master else 0)
                and device['attributes']['link-group'] == group
                and set(links['dum98']['addresses']) <= kernel.addresses('dum98').keys())

    try:
        # Commit check accepts a proposed VRF before its kernel device exists.
        client.request('validate', owner='dummy', links=links)
        client.replace('vrf', {'BLUE': {'kind': 'vrf', 'attributes': {'table': 100}},
                               'RED': {'kind': 'vrf', 'attributes': {'table': 256}}})
        client.replace('dummy', links)
        assert member('BLUE', 4294967295)

        # A configured move preserves both address families and moves connected routes.
        links['dum98']['attributes'] = {'vrf': 'RED', 'link-group': 10}
        client.replace('dummy', links)
        assert member('RED', 10)
        assert '192.0.2.0/24' in run('ip', 'route', 'show', 'table', '256')

        # External membership/group changes and loss of either device are repaired.
        run('ip', 'link', 'set', 'dum98', 'nomaster', 'group', '11')
        wait_for(lambda: member('RED', 10))
        run('ip', 'link', 'del', 'RED')
        wait_for(lambda: kernel.device('RED') is not None and member('RED', 10))
        run('ip', 'link', 'del', 'dum98')
        wait_for(lambda: member('RED', 10))

        process.terminate()
        process.wait(timeout=10)
        restart()
        wait_for(lambda: member('RED', 10))

        # Removing the leaves explicitly restores the default domain and group.
        links['dum98']['attributes'] = {'vrf': '', 'link-group': 0}
        client.replace('dummy', links)
        assert member('', 0)
        assert '192.0.2.0/24' in run('ip', 'route', 'show', 'table', 'main')
    finally:
        client.replace('dummy', {}, recovery=True)
        client.replace('vrf', {}, recovery=True)
        kernel.close()


def test_real_ethernet_membership_failure_restores_old_vrf_and_group(daemon):
    client, _, _ = daemon
    kernel = Kernel()
    run('ip', 'link', 'add', 'eth98', 'type', 'veth', 'peer', 'name', 'nvyrpeer98')
    run('ip', 'link', 'set', 'nvyrpeer98', 'up')

    try:
        client.replace('vrf', {'BLUE': {'kind': 'vrf', 'attributes': {'table': 100}},
                               'RED': {'kind': 'vrf', 'attributes': {'table': 256}}})
        links = {'eth98': {'kind': 'ethernet', 'attributes': {'vrf': 'BLUE', 'link-group': 10},
                          'addresses': ['192.0.2.98/24', '2001:db8::98/64']}}
        client.replace('ethernet', links)
        broken = deepcopy(links)
        broken['eth98']['attributes'].update(vrf='RED', mtu=1, **{'link-group': 20})

        # Fail after changing master, exercising compensation of the partial move.
        with pytest.raises(RouterError, match='previous configuration restored'):
            client.replace('ethernet', broken)

        device = kernel.device('eth98')
        assert device['attributes']['vrf'] == kernel.device('BLUE')['index']
        assert device['attributes']['link-group'] == 10
        assert set(links['eth98']['addresses']) <= kernel.addresses('eth98').keys()

        client.replace('ethernet', {})
        assert kernel.device('eth98')['attributes']['vrf'] == 0
        assert kernel.device('eth98')['attributes']['link-group'] == 0
    finally:
        client.replace('ethernet', {}, recovery=True)
        client.replace('vrf', {}, recovery=True)
        run('ip', 'link', 'del', 'eth98')
        kernel.close()
