"""Default-VRF DHCP hostname publication and installed hook lifecycle."""

import json
from pathlib import Path

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from nvyr.helpers import dhcp_hosts, hosts, kea
from nvyr.helpers.process import cmd
from nvyr.tree import lookup
from smoketests.assertions import (
    assert_config_names_unused, assert_equal, assert_not_in, assert_raises,
)
from smoketests.support import configuration_case, prepared_test


@pytest.fixture(scope='module')
def hostfile_suite(config, request):
    """Use a private default-VRF link; the suite restores the original DHCP config."""
    prepared = False

    def standup(session):
        nonlocal prepared
        running = session.get_config()
        assert_config_names_unused(running, 'dum984', 'HOSTFILESMOKE')
        links = json.loads(cmd(['ip', '-j', 'link', 'show']))
        assert_not_in('dum984', [link['ifname'] for link in links])
        prepared = True

        for server in ('dhcp-server', 'dhcpv6-server'):
            if lookup(running, ('service', server), None) is not None:
                session.delete(f'delete service {server}')
        session.set('set interfaces dummy dum984 address 198.18.214.1/24')
        session.set('set interfaces dummy dum984 address 2001:db8:214::1/64')
        session.set('set service dhcpv6-server listen-interface dum984')
        session.set('set service dhcpv6-server shared-network HOSTFILESMOKE subnet 2001:db8:214::/64 range 2001:db8:214::10-2001:db8:214::20')
        session.set('set service dhcp-server listen-interface dum984')
        session.set('set service dhcp-server shared-network HOSTFILESMOKE subnet 198.18.214.0/24 range 198.18.214.10-198.18.214.20')
        session.commit()

    def cleanup(session):
        if not prepared:
            return
        session.discard()
        running = session.get_config()
        for server in ('dhcp-server', 'dhcpv6-server'):
            if lookup(running, ('service', server), None) is not None:
                session.delete(f'delete service {server}')
        session.commit()
        if lookup(session.get_config(), ('interfaces', 'dummy', 'dum984'), None) is not None:
            session.delete('delete interfaces dummy dum984')
            session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def hostfile_environment(config, request, hostfile_suite):
    """Restore case settings in one commit while retaining unchanged suite objects."""
    with configuration_case(config, request, hostfile_suite):
        yield


@pytest.mark.parametrize(('family', 'server'), [(4, 'dhcp-server'), (6, 'dhcpv6-server')])
def test_hostfile_hook_enable_and_remove(config, family, server):
    """The real Kea daemon loads the installed hook and unloads it on removal."""
    original_hosts = Path('/etc/hosts').read_text()
    config.set(f'set service {server} update-hostfile')
    config.commit()

    socket = kea.RUNTIME / (kea.instance_name(family, 'default') + '.sock')
    native = kea.control(socket, 'config-get')['arguments']
    assert_equal(dhcp_hosts.enabled(native), True)
    assert_equal(Path(dhcp_hosts.HOOK_SCRIPT).is_file(), True)
    assert_equal(Path(dhcp_hosts.HOOK_LIBRARY).is_file(), True)
    unmanaged, _ = hosts.split_dhcp(Path('/etc/hosts').read_text())
    assert_equal(unmanaged, original_hosts)

    config.delete(f'delete service {server} update-hostfile')
    config.commit()
    native = kea.control(socket, 'config-get')['arguments'][f'Dhcp{family}']
    assert_equal(native['hooks-libraries'], [])
    assert_equal(Path('/etc/hosts').read_text(), original_hosts)


def test_hostfile_server_disable(config):
    """Disabling the server removes its runtime config and managed hosts section."""
    config.set('set service dhcp-server update-hostfile')
    config.commit()
    config.set('set service dhcp-server disable')
    config.commit()

    assert_equal((kea.RUNTIME / (kea.instance_name(4, 'default') + '.json')).exists(), False)
    assert_not_in('# BEGIN nVyR DHCP hosts', Path('/etc/hosts').read_text())


def test_hostfile_global_only(config):
    """Named VRF configurations cannot publish into the global hosts namespace."""
    with assert_raises(RouterError, match='Unknown command|unknown'):
        config.set('set vrf name HOSTFILESMOKE service dhcp-server update-hostfile')
    config.discard()

    with assert_raises(RouterError, match='Unknown command|unknown'):
        config.set('set vrf name HOSTFILESMOKE service dhcpv6-server update-hostfile')
    config.discard()
