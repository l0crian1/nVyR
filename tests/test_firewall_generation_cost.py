"""Sparse configurations must not pay for every possible dependency or match."""

import pytest

from nvyr import schema as schema_module
from nvyr.helpers import dependencies, nftables_formatters as nft
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree, lookup


@pytest.fixture(scope='module')
def registrar():
    return dependencies.Dependencies(Schema.bundled())


@pytest.fixture
def configuration():
    return {
        'interfaces': {'dummy': {'dum0': {'vrf': 'BLUE'}, 'dum1': {}}},
        'vrf': {'name': {'BLUE': {'table': '100'}}},
        'firewall': {
            'group': {'interface-group': {'LAN': {'interface': ['dum0', 'dum1']}}},
            'ipv4': {
                'name': {'CUSTOM': {'rule': {'10': {
                    'action': 'accept', 'inbound-interface': ['dum0'],
                    'not': {'inbound-interface-group': 'LAN'},
                }}}},
                'forward': {'filter': {'rule': {
                    '10': {'action': 'jump', 'jump-target': 'CUSTOM'},
                    '20': {'action': 'accept', 'inbound-interface': ['dum1']},
                    '30': {'map': 'SERVICES'},
                }}},
            },
        },
    }


@pytest.mark.parametrize('category', ['dependency', 'depends', 'reapply-on-change'])
@pytest.mark.parametrize('read_only', [False, True])
@pytest.mark.parametrize('path', [
    '', 'interfaces', 'interfaces dummy', 'interfaces dummy dum0',
    'interfaces dummy dum1', 'interfaces dummy absent', 'interfaces dummy dum0 vrf',
    'firewall', 'firewall ipv4 name', 'firewall ipv4 name CUSTOM rule 10 not',
    'firewall group interface-group LAN interface',
    'firewall ipv4 forward filter rule 10 jump-target', 'vrf name BLUE',
])
def test_snapshot_dependencies_match_projected_collection(registrar, configuration, category, read_only, path):
    """Whole trees, empty providers, negation, multi leaves and scoped reads agree."""
    tree = ReadOnlyTree(configuration) if read_only else configuration
    scope = tuple(path.split())
    expected = registrar.collect(
        lambda location: lookup(tree, location),
        lambda location: lookup(tree, location, {}), category, scope)

    assert registrar.from_tree(tree, category, scope) == expected


def test_snapshot_walk_does_not_repeat_root_lookups(registrar, monkeypatch):
    """Many unrelated rule fields must not multiply full configuration-path reads."""
    calls = []

    def tracked_lookup(tree, path):
        calls.append(path)
        return lookup(tree, path)

    monkeypatch.setattr(dependencies, 'lookup', tracked_lookup)
    rules = {str(number): {'action': 'accept', 'source-address': {'192.0.2.1': {}}}
             for number in range(100)}
    tree = ReadOnlyTree({'firewall': {'ipv4': {'forward': {'filter': {'rule': rules}}}}})

    assert registrar.from_tree(tree, 'depends') == set()
    assert calls == [()]


def test_defaults_skip_tag_subtrees_without_default_declarations(monkeypatch):
    """Default expansion must not enumerate unrelated instances or their fields."""
    schema = Schema({'kind': 'node', 'children': {
        'objects': {'kind': 'tag_node', 'children': {'value': {'kind': 'leaf_node'}}},
        'service': {'kind': 'node', 'children': {
            'enabled': {'kind': 'leaf_node', 'valueless': True,
                        'default': {'mode': 'always'}},
        }},
    }})
    explicit = {'objects': {'one': {'value': 'example'}}, 'service': {}}

    def checked_lookup(tree, path, *args):
        assert not path or path[0] != 'objects'
        return lookup(tree, path, *args)

    monkeypatch.setattr(schema_module, 'lookup', checked_lookup)

    assert schema.defaults(explicit) == {
        'objects': {'one': {'value': 'example'}}, 'service': {'enabled': True},
    }
    assert explicit['service'] == {}


def test_rule_formatter_reads_only_present_fields(monkeypatch):
    """Positive/negative sides must not probe absent keys or repeat value lookups."""
    original = nft.nft_field_value
    calls = []

    def tracked_value(configuration, field, default=None, *, negative=False):
        calls.append((field, negative))
        return original(configuration, field, default, negative=negative)

    monkeypatch.setattr(nft, 'nft_field_value', tracked_value)
    rule = ReadOnlyTree({
        'action': 'accept', 'protocol': ['tcp'], 'destination-port': ['22'],
        'source-address': {'192.0.2.1': {}}, 'counter': {},
        'connection': {'original': {'not': {'destination-address': ['198.51.100.1']}}},
    })

    text = nft.nft_rule('ipv4', 'forward', '10', rule)

    assert 'ct original ip daddr != { 198.51.100.1 }' in text
    assert calls == [
        ('source-address', False), ('protocol', False), ('destination-port', False),
        ('connection-original-destination-address', True), ('counter', False),
    ]


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_sparse_selection_preserves_full_scan_output(family, monkeypatch):
    """Canonical order remains independent of input order, with both polarities."""
    source = '192.0.2.1' if family == 'ipv4' else '2001:db8::1'
    rule = {
        'action': 'accept', 'log': {'level': 'warning'}, 'counter': {},
        'last-used': {}, 'destination-port': ['443', '22'], 'protocol': ['tcp'],
        'source-address': {source: {}}, 'tcp-flags': ['syn,not ack'],
        'connection': {'state': ['established'], 'original': {'not': {'destination-port': ['23']}}},
        'not': {'source-port': ['25'], 'source-address': {source: {}}},
    }
    selected = nft.nft_rule(family, 'forward', '10', rule)

    # Recreate the old enumeration as an independent output-equivalence reference.
    monkeypatch.setattr(nft, 'nft_present_fields', lambda *args, **kwargs: set(nft.NFT_KEYMAP))
    scanned = nft.nft_rule(family, 'forward', '10', dict(reversed(list(rule.items()))))

    assert selected == scanned
