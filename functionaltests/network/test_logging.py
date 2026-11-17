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
from smoketests.logging_support import CONNTRACK_LOG, check_connection_events, connection_exchange
from smoketests.support import wait_for


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


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('protocol', ['tcp', 'udp'])
def test_connection_events_include_both_direction_counters(config, family, protocol):
    """The shared collector observes real flows without rebuilding network state."""
    check_connection_events(family, protocol)


def test_connection_event_and_protocol_selection(config):
    """Destroy-only UDP selection excludes TCP and other event classes."""
    config.delete('delete firewall global-options connection-tracking logging')
    config.set('set firewall global-options connection-tracking logging event destroy filter protocol udp')
    config.commit()
    offset = CONNTRACK_LOG.stat().st_size
    excluded = connection_exchange(protocol='tcp')
    included = connection_exchange(protocol='udp')
    text = wait_for(lambda: CONNTRACK_LOG.read_bytes()[offset:].decode(), lambda text: included in text,
                    description='selected UDP destroy event')
    assert excluded not in text
    assert '[NEW]' not in text and '[UPDATE]' not in text
    assert_in('[DESTROY]', text)


def test_connection_log_rotation_keeps_collector_running(config):
    """HUP reopens the rotated file without dropping/recreating its subscription."""
    from nvyr.helpers import logging_runtime

    unit = 'nvyr-conntrack-log.service'
    before = cmd(['systemctl', 'show', '--property=MainPID', '--value', unit]).strip()
    rotated = CONNTRACK_LOG.with_name('conntrack.rotation-test')
    assert not rotated.exists()
    CONNTRACK_LOG.rename(rotated)
    try:
        logging_runtime.reopen()
        wait_for(CONNTRACK_LOG.exists, bool, description='reopened connection log')
        check_connection_events()
        after = cmd(['systemctl', 'show', '--property=MainPID', '--value', unit]).strip()
        assert before == after
    finally:
        # Retain the pre-rotation records as a normal rotation archive.
        rotated.rename(CONNTRACK_LOG.with_name('conntrack.rotation-test.log'))


def test_icmp_connection_text_has_correct_type_and_code(config):
    """Exercise the patched native PRINTFLOW formatter with an actual echo request."""
    offset = CONNTRACK_LOG.stat().st_size
    cmd(['ping', '-c', '1', '-W', '2', '-e', '41701', '127.0.0.1'])
    cmd(['conntrack', '-D', '-f', 'ipv4', '-p', 'icmp', '-s', '127.0.0.1',
         '-d', '127.0.0.1', '--icmp-id', '41701'])
    text = wait_for(lambda: CONNTRACK_LOG.read_bytes()[offset:].decode(),
                    lambda text: '[DESTROY]' in text and 'PROTO=ICMP ' in text,
                    description='ICMP connection text')
    assert_in('PROTO=ICMP TYPE=8 CODE=0', text)
    assert 'TYPE=0 CODE=8' not in text


def test_connection_log_preserves_original_and_translated_tuple(config):
    """The shared NAT rule translates only this test's loopback source."""
    offset = CONNTRACK_LOG.stat().st_size
    identity = connection_exchange(source='127.0.0.77')
    text = wait_for(lambda: CONNTRACK_LOG.read_bytes()[offset:].decode(),
                    lambda text: any(identity in line and '[DESTROY]' in line for line in text.splitlines()),
                    description='translated connection record')
    line = next(line for line in text.splitlines() if identity in line and '[DESTROY]' in line)
    assert_in('ORIG: SRC=127.0.0.77 DST=127.0.0.1', line)
    assert_in('REPLY: SRC=127.0.0.1 DST=127.0.0.78', line)
