"""IPv4 imported-map refresh and IPv6 imported match-group on the shared routed network.

No additional topology. Uses exclusive UDP ports 59411/59412 and restores the feed after mutation.
"""

from contextlib import closing
from pathlib import Path

from nvyr.protocol import Client
from functionaltests.routed_network import assert_traffic


def refresh():
    with closing(Client('/run/nvyr/configd.sock')) as client:
        return client.request('firewall-list-update', kind='map', family='ipv4', name='RNFEED')['text']


def test_imported_map_refresh_without_commit(config):
    source = Path('/run/nvyr-routed-feeds/ipv4.csv')
    before = source.read_text()
    assert_traffic('ipv4', 59411, allowed=False)
    try:
        source.write_text(before.replace('drop', 'accept'))
        assert 'replaced membership in 1' in refresh()
        assert_traffic('ipv4', 59411)
        assert 'replaced membership in 0' in refresh()
    finally:
        source.write_text(before)
        refresh()


def test_imported_ipv6_tuple(config):
    assert_traffic('ipv6', 59412, allowed=False)
