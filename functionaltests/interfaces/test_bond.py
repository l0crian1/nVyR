"""Dual-stack forwarding over a redundant pair; failover uses dedicated veths in the shared interface suite."""

from pathlib import Path

from smoketests.assertions import assert_ping_reply


def test_active_backup_failover(config):
    for address in ('198.18.180.2', '2001:db8:180::2'):
        assert_ping_reply(address, vrf='NVYRIFSMOKE')

    config.set('set interfaces virtual-ethernet veth43900 disable')
    config.commit()
    for address in ('198.18.180.2', '2001:db8:180::2'):
        assert_ping_reply(address, vrf='NVYRIFSMOKE')
    assert Path('/sys/class/net/bond43900/bonding/active_slave').read_text().strip() == 'veth43902'
