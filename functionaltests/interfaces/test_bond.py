"""Dual-stack failover and LACP negotiation on the shared bond pair.

Both modes reuse the same member links and VRFs. The LACP phase changes both
ends together; an external switch or physical partner is not required.
"""

from pathlib import Path

from smoketests.assertions import assert_ping_reply
from smoketests.support import wait_for


def test_active_backup_failover(config):
    for address in ('198.18.180.2', '2001:db8:180::2'):
        assert_ping_reply(address, vrf='NVYRIFSMOKE')

    config.set('set interfaces virtual-ethernet veth43900 disable')
    config.commit()
    for address in ('198.18.180.2', '2001:db8:180::2'):
        assert_ping_reply(address, vrf='NVYRIFSMOKE')
    assert Path('/sys/class/net/bond43900/bonding/active_slave').read_text().strip() == 'veth43902'


def test_lacp_forwarding(config):
    # Restore the member disabled by the failover case without rebuilding either pair.
    config.delete('delete interfaces virtual-ethernet veth43900 disable')
    for name in ('bond43900', 'bond43901'):
        config.delete(f'delete interfaces bond {name} primary')
        config.set(f'set interfaces bond {name} mode 802.3ad')
        config.set(f'set interfaces bond {name} lacp rate fast min-links 2')
        config.set(f'set interfaces bond {name} transmit-hash-policy layer3+4')
    config.commit()

    def collecting():
        for name in ('bond43900', 'bond43901'):
            state = Path(f'/proc/net/bonding/{name}').read_text()
            # Each member must synchronize, collect and distribute, not merely have carrier.
            actor_states = [int(line.split(':', 1)[1]) for line in state.splitlines()
                            if line.strip().startswith('port state:')]
            if len(actor_states) != 4 or any(value & 0x38 != 0x38 for value in actor_states):
                return False
        return True

    wait_for(collecting, bool, timeout=30, description='both LACP members collecting and distributing')
    for address in ('198.18.180.2', '2001:db8:180::2'):
        assert_ping_reply(address, vrf='NVYRIFSMOKE')
