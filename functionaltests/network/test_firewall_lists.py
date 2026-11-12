"""Imported packets, refresh, malformed/conflicting rows and unavailable sources.

No additional topology. Uses exclusive UDP ports 59411/59412 and restores the feed after mutation.
"""

from contextlib import closing
from pathlib import Path

from nvyr.helpers.process import cmd
from nvyr.protocol import Client
from functionaltests.routed_network import assert_traffic


def refresh():
    with closing(Client('/run/nvyr/configd.sock')) as client:
        return client.request('firewall-list-update', kind='map', family='ipv4', name='RNFEED')['text']


def test_imported_map_refresh_without_commit(config):
    source = Path('/run/nvyr-routed-feeds/ipv4.csv')
    before = source.read_text()
    rule = next(line for line in cmd(['nft', '-a', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_forward']).splitlines()
                if '@ipv4_map_RNFEED' in line)
    assert_traffic('ipv4', 59411, allowed=False)
    try:
        source.write_text(before.replace('drop', 'accept'))
        assert 'replaced membership in 1' in refresh()
        assert_traffic('ipv4', 59411)
        assert 'replaced membership in 0' in refresh()
        assert rule in cmd(['nft', '-a', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_forward']).splitlines()
    finally:
        source.write_text(before)
        refresh()


def test_bad_rows_and_conflicts_do_not_discard_unrelated_entries(config):
    source = Path('/run/nvyr-routed-feeds/ipv4.csv')
    before = source.read_text()
    try:
        # Conflicting results remove every occurrence of that key. A malformed
        # unrelated row must not prevent the valid blocking tuple from loading.
        unrelated = '192.0.2.1,198.51.100.1,443,tcp,'
        source.write_text(before + 'not-an-address,198.51.100.1,443,tcp,drop\n'
                          + unrelated + 'drop\n' + unrelated + 'accept\n')
        refresh()
        assert_traffic('ipv4', 59411, allowed=False)
        members = cmd(['nft', 'list', 'map', 'inet', 'nvyr_filter', 'ipv4_map_RNFEED'])
        assert '192.0.2.1' not in members
        assert '198.18.61.2' in members

        # Ambiguity in the actual traffic tuple must remove both results, allowing
        # the existing hook default to decide, rather than selecting one result.
        source.write_text(before + before.replace('drop', 'accept'))
        refresh()
        assert_traffic('ipv4', 59411)
    finally:
        source.write_text(before)
        refresh()


def test_unavailable_source_keeps_last_published_membership(config):
    source = Path('/run/nvyr-routed-feeds/ipv4.csv')
    before = source.read_text()
    try:
        source.unlink()
        assert 'using cached membership' in refresh()
        assert_traffic('ipv4', 59411, allowed=False)
        assert '198.18.61.2' in cmd(['nft', 'list', 'map', 'inet', 'nvyr_filter', 'ipv4_map_RNFEED'])
    finally:
        source.write_text(before)
        refresh()


def test_imported_ipv6_tuple(config):
    assert_traffic('ipv6', 59412, allowed=False)
