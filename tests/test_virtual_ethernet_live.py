"""Real veth lifecycle tests, restricted to an isolated privileged container."""

from copy import deepcopy
import os

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from tests.test_netlink import Leases
from tests.test_netlink_live import daemon, isolated, run, wait_for

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETLINK_TEST') != '1',
                                reason='requires isolated privileged Netlink container')


def pair():
    """Use names reserved to this disposable test namespace."""
    return {
        'veth90': {'kind': 'virtual-ethernet', 'attributes': {'peer-name': 'veth91', 'link-group': 90},
                   'addresses': ['192.0.2.0/31', '2001:db8::90/64']},
        'veth91': {'kind': 'virtual-ethernet', 'attributes': {'peer-name': 'veth90', 'description': 'peer'},
                   'addresses': ['192.0.2.1/31', '2001:db8::91/64']},
    }


def test_real_pair_create_recover_restart_and_delete(daemon):
    """One create yields two owned endpoints; losing either restores the pair."""
    client, process, restart = daemon
    kernel = Kernel()
    links = pair()

    def ready():
        return all(kernel.device(name) is not None and kernel.device(name)['up']
                   and set(spec['addresses']) <= kernel.addresses(name).keys()
                   for name, spec in links.items())

    try:
        client.replace('virtual-ethernet', links)
        assert ready()
        first = kernel.device('veth90')
        second = kernel.device('veth91')
        assert first['message'].get_attr('IFLA_LINK') == second['index']
        assert first['attributes']['link-group'] == 90
        assert second['attributes']['description'] == 'peer'

        # Direct daemon clients cannot delete one endpoint or replace its peer.
        with pytest.raises(RouterError, match='configure virtual-ethernet'):
            client.replace('virtual-ethernet', {'veth90': links['veth90']})

        rewired = deepcopy(links)
        rewired['veth92'] = rewired.pop('veth91')
        rewired['veth90']['attributes']['peer-name'] = 'veth92'
        with pytest.raises(RouterError, match='delete and commit the pair'):
            client.replace('virtual-ethernet', rewired)

        assert kernel.device('veth90')['index'] == first['index']

        run('ip', 'link', 'del', 'veth91')
        wait_for(ready)

        process.terminate()
        process.wait(timeout=10)
        run('ip', 'link', 'del', 'veth90')
        restart()
        wait_for(ready)

        client.replace('virtual-ethernet', {})
        assert kernel.device('veth90') is None and kernel.device('veth91') is None
    finally:
        client.replace('virtual-ethernet', {}, recovery=True)
        kernel.close()


def test_real_pair_failure_rolls_back_both_endpoints(tmp_path, isolated):
    """Failure configuring the second endpoint removes both newly created devices."""
    kernel = Kernel()
    manager = Manager(kernel, Leases(), tmp_path)
    links = pair()
    links['veth91']['attributes']['mtu'] = 1

    try:
        with pytest.raises(RouterError, match='previous configuration restored'):
            manager.replace('virtual-ethernet', links)

        assert kernel.device('veth90') is None and kernel.device('veth91') is None
        assert manager.state['records'] == {} and manager.state['pending'] == {}
    finally:
        manager.replace('virtual-ethernet', {}, recovery=True)
        kernel.close()


def test_real_pair_vrf_membership_disable_and_failed_update(daemon):
    """Endpoint settings are independent and failed updates restore the original pair."""
    client, _, _ = daemon
    kernel = Kernel()
    links = pair()
    links['veth90']['attributes']['vrf'] = 'VETHBLUE'
    links['veth91']['attributes']['vrf'] = 'VETHRED'

    try:
        client.replace('vrf', {'VETHBLUE': {'kind': 'vrf', 'attributes': {'table': 190}},
                               'VETHRED': {'kind': 'vrf', 'attributes': {'table': 191}}})
        client.replace('virtual-ethernet', links)
        original_index = kernel.device('veth90')['index']
        assert kernel.device('veth90')['attributes']['vrf'] == kernel.device('VETHBLUE')['index']
        assert kernel.device('veth91')['attributes']['vrf'] == kernel.device('VETHRED')['index']
        run('ip', 'vrf', 'exec', 'VETHBLUE', 'ping', '-c', '1', '-W', '2', '192.0.2.1')
        run('ip', 'vrf', 'exec', 'VETHBLUE', 'ping', '-6', '-c', '1', '-W', '2', '2001:db8::91')

        broken = deepcopy(links)
        broken['veth90']['attributes']['link-group'] = 99
        broken['veth91']['attributes']['mtu'] = 1
        with pytest.raises(RouterError, match='previous configuration restored'):
            client.replace('virtual-ethernet', broken)
        assert kernel.device('veth90')['index'] == original_index
        assert kernel.device('veth90')['attributes']['link-group'] == 90

        links['veth91']['disabled'] = True
        client.replace('virtual-ethernet', links)
        assert kernel.device('veth90')['up'] and not kernel.device('veth91')['up']
    finally:
        client.replace('virtual-ethernet', {}, recovery=True)
        client.replace('vrf', {}, recovery=True)
        kernel.close()


def test_real_pair_foreign_endpoint_is_not_adopted(daemon):
    """An unrelated pre-existing pair must survive a rejected ownership claim."""
    client, _, _ = daemon
    kernel = Kernel()
    run('ip', 'link', 'add', 'veth90', 'type', 'veth', 'peer', 'name', 'veth91')
    index = kernel.device('veth90')['index']

    try:
        with pytest.raises(RouterError, match='not owned'):
            client.replace('virtual-ethernet', pair())
        assert kernel.device('veth90')['index'] == index
    finally:
        run('ip', 'link', 'del', 'veth90')
        kernel.close()
