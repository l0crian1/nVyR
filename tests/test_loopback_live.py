"""Real loopback lifecycle; run only in an isolated privileged container."""

import os

import pytest

from nvyr.config_scripts.interface_loopback import generate
from nvyr.errors import RouterError
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from tests.test_netlink import Leases
from tests.test_netlink_live import isolated

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETLINK_TEST') != '1',
                                reason='requires isolated privileged Netlink container')


@pytest.fixture
def loopback(tmp_path, isolated):
    """Keep the permanent device alive when releasing each test's configuration."""
    kernel = Kernel()
    manager = Manager(kernel, Leases(), tmp_path)
    try:
        yield manager, kernel, tmp_path
    finally:
        manager.replace('loopback', {}, recovery=True)
        kernel.close()


def test_addresses_description_removal_and_release(loopback):
    """Replace and delete owned settings without changing lo's identity or defaults."""
    manager, kernel, _ = loopback
    index = kernel.device('lo')['index']
    manager.replace('loopback', generate({'lo': {'address': ['192.0.2.1/32', '2001:db8::1/128'],
                                                'description': 'Loopback native test'}}, None))
    assert kernel.device('lo')['attributes']['description'] == 'Loopback native test'
    assert {'127.0.0.1/8', '::1/128', '192.0.2.1/32', '2001:db8::1/128'} <= kernel.addresses('lo').keys()

    manager.replace('loopback', generate({'lo': {'address': ['2001:db8::1/128']}}, None))
    assert '192.0.2.1/32' not in kernel.addresses('lo')
    assert kernel.device('lo')['attributes']['description'] == ''
    manager.replace('loopback', {})

    assert set(kernel.addresses('lo')) == {'127.0.0.1/8', '::1/128'}
    assert kernel.device('lo')['up']
    assert kernel.device('lo')['index'] == index


def test_restart_and_reconciliation(loopback):
    """Persisted ownership recovers drift without replacing the loopback device."""
    manager, kernel, directory = loopback
    definition = generate({'lo': {'address': ['192.0.2.1/32']}}, None)
    manager.replace('loopback', definition)
    restarted = Manager(kernel, Leases(), directory)
    kernel.ipr.addr('del', index=kernel.device('lo')['index'], address='192.0.2.1', prefixlen=32)
    restarted.reconcile()

    assert not restarted.failures
    assert '192.0.2.1/32' in kernel.addresses('lo')
    restarted.replace('loopback', {})


def test_failed_update_restores_prior_addresses(loopback, monkeypatch):
    """A failed address update compensates back to the previous loopback settings."""
    manager, kernel, _ = loopback
    manager.replace('loopback', generate({'lo': {'address': ['192.0.2.1/32']}}, None))
    original = kernel.set_addresses
    fail = True

    def fail_once(name, addresses, **options):
        nonlocal fail
        if fail:
            fail = False
            raise RouterError('Simulated address failure')
        return original(name, addresses, **options)

    monkeypatch.setattr(kernel, 'set_addresses', fail_once)
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.replace('loopback', generate({'lo': {'address': ['192.0.2.2/32'], 'description': 'New'}}, None))

    assert set(kernel.addresses('lo')) == {'127.0.0.1/8', '::1/128', '192.0.2.1/32'}
    assert kernel.device('lo')['attributes']['description'] == ''
    assert kernel.device('lo')['up']
