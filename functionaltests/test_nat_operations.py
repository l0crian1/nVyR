"""Inspect installed SNAT, DNAT, exclusions, maps and rule-detail output.

All populated views share one native ruleset for the module. The empty-view case
uses a separate empty namespace; neither scenario changes the host firewall.
"""

import json

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.helpers.process import cmd
from smoketests.assertions import assert_equal, assert_in, assert_not_in
from smoketests.namespace_support import namespace as empty_namespace
from functionaltests.native_network import native_namespace


def install(namespace, tmp_path, contents):
    """Install only this test's ruleset; the namespace fixture removes it afterward."""
    path = tmp_path / 'nat.nft'
    path.write_text(contents)
    cmd(['ip', 'netns', 'exec', namespace, 'nft', '-f', str(path)])


def show(namespace, direction, *options):
    """Use the operational script, including its native JSON normalizer and formatting."""
    return cmd(['ip', 'netns', 'exec', namespace, 'python3', '-m', 'nvyr.op_scripts.nat',
                'show', '--direction', direction, *options])


@pytest.fixture(scope='module')
def namespace(native_namespace, tmp_path_factory):
    """Install every compatible native NAT rule in one transaction."""
    install(native_namespace, tmp_path_factory.mktemp('nat-views'), '''
table inet nvyr_filter {
    map ipv4_map_WEB {
        type ipv4_addr : ipv4_addr
        elements = { 198.51.100.22 : 10.0.0.12 }
    }
    chain ipv4_nat_postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 192.0.2.10 counter snat ip to 203.0.113.1 comment "20|source translation"
        ip saddr 192.0.2.11 counter masquerade comment "10|masquerade"
        ip saddr 192.0.2.12 return comment "30|excluded"
    }
    chain ipv4_nat_prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip daddr 198.51.100.20 tcp dport 443 counter dnat ip to 10.0.0.10:8443 comment "10|web"
        ip daddr 198.51.100.21 counter dnat ip to 10.0.0.11 comment "20|other"
        meta nfproto ipv4 counter dnat ip to ip daddr map @ipv4_map_WEB comment "30|mapped"
    }
}
''')
    return native_namespace


def test_source_rules(namespace):
    """Source NAT shows explicit translation, masquerade and exclusions in installed order."""
    records = json.loads(show(namespace, 'source', '--raw'))
    assert_equal([record['number'] for record in records], ['20', '10', '30'])
    assert_equal(records[0]['translation']['address'], '203.0.113.1')
    assert_equal(records[0]['counter']['packets'], 0)
    assert_not_in('counter', records[2])
    output = show(namespace, 'source')
    assert_in('masquerade', output)
    assert_in('exclude', output)
    assert_in('Packets', output)


def test_destination_rule_detail(namespace):
    """Selecting one destination rule retains matches and the translated address/port."""
    records = json.loads(show(namespace, 'destination', '--rule', '10', '--raw'))
    assert_equal(len(records), 1)
    assert_equal(records[0]['translation'], {'address': '10.0.0.10', 'port': 8443})
    output = show(namespace, 'destination', '--rule', '10', '--detail')
    assert_in('Rule 10', output)
    assert_not_in('Rule 20', output)
    assert_in(' | ', output)
    assert_in('198.51.100.20', output)
    assert_in('10.0.0.10', output)


def test_destination_map(namespace):
    """NAT maps remain named targets, without attempting to guess a single translated address."""
    output = show(namespace, 'destination')
    assert_in('map WEB', output)
    record = json.loads(show(namespace, 'destination', '--rule', '30', '--raw'))[0]
    assert_equal(record['map'], 'WEB')
    assert_equal(record['map-fields'], ['destination-address'])


def test_empty_nat_views(empty_namespace):
    """A router with no installed NAT rules displays an empty result, not an exception."""
    namespace = empty_namespace
    assert_in('No rules installed.', show(namespace, 'source'))
    assert_in('No rules installed.', show(namespace, 'destination'))
