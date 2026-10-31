"""Global rotation, daemon severity and exact IPv4/IPv6 NFLOG rule selection.

Both log groups and rules coexist with the network baseline. The tests emit
independent loopback traffic; destructive log truncation is incompatible.
"""

from pathlib import Path
import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_in, assert_log_output


def test_global_rotation_and_service_override(config):
    """One rotation policy covers service, packet and container logs."""
    # Installed once by configs/network-services.conf.

    rotation = Path('/run/nvyr-logging/logrotate.conf').read_text()
    assert_in('size 64M', rotation)
    assert_in('rotate 3', rotation)
    cmd(['logger', '-t', 'bgpd', '-p', 'daemon.debug', 'nvyr-smoke-bgp-debug'])
    assert_log_output('bgp', expected=('nvyr-smoke-bgp-debug',))


def test_ipv4_nflog_group_and_exact_input_rule(config):
    """Receive actual IPv4 packets and select only this input/filter rule."""
    # Installed once by configs/network-services.conf.

    cmd(['ping', '-c', '1', '-W', '2', '127.0.0.1'])
    assert_log_output('firewall', '--group', 'SMOKELOG4', expected=('[ipv4-INP-filter-10-A]', 'SRC=127.0.0.1'))
    assert_log_output('firewall', '--family', 'ipv4', '--hook', 'input', '--stage', 'filter', '--rule', '10',
                      expected=('[ipv4-INP-filter-10-A]',), absent=('[ipv6-', '[ipv4-OUT-', '-100-A]'))


def test_ipv6_nflog_group_and_exact_input_rule(config):
    """IPv6 packet logging has its own family selector and collector file."""
    # Installed once by configs/network-services.conf.

    cmd(['ping', '-6', '-c', '1', '-W', '2', '::1'])
    assert_log_output('firewall', '--group', 'SMOKELOG6', expected=('[ipv6-INP-filter-10-A]',))
    assert_log_output('firewall', '--family', 'ipv6', '--hook', 'input', '--stage', 'filter', '--rule', '10',
                      expected=('[ipv6-INP-filter-10-A]',), absent=('[ipv4-', '[ipv6-OUT-'))


def test_dhcp_logs_separate_vrfs(config):
    """The collector routes each instance marker into its own selected file."""
    cmd(['logger', '-t', 'kea-dhcp4', '-p', 'local0.info', '[nvyr-kea-4-4c4f47424c5545] nvyr-log-blue'])
    cmd(['logger', '-t', 'kea-dhcp4', '-p', 'local0.info', '[nvyr-kea-4-4c4f47524544] nvyr-log-red'])

    assert_log_output('dhcp-server', '--vrf', 'LOGBLUE', expected=('nvyr-log-blue',), absent=('nvyr-log-red',))
    assert_log_output('dhcp-server', '--vrf', 'LOGRED', expected=('nvyr-log-red',), absent=('nvyr-log-blue',))
