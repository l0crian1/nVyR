"""Keep feature verification conditional without overlooking inherited matches."""

import pytest

from nvyr.config_scripts import firewall, nat
from nvyr.errors import ValidationError
from nvyr.helpers import nftables, nftables_connection, nftables_formatters, nftables_zones
from nvyr.tree import ReadOnlyTree


RULE_PATH = ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10')


def unexpected_work(*args, **kwargs):
    raise AssertionError('Verification visited an unrelated feature')


def test_ordinary_rule_skips_unrelated_feature_work(monkeypatch):
    """An address rule must not inspect absent features or scan group entries."""
    for helper in ('verify_fib', 'verify_limits', 'verify_quota', 'verify_group_update',
                   '_verify_offload_status', 'nft_interface_contexts'):
        monkeypatch.setattr(firewall, helper, unexpected_work)

    for helper in ('verify_icmp', 'verify_ports', 'match_protocols'):
        monkeypatch.setattr(nftables, helper, unexpected_work)

    monkeypatch.setattr(nftables_connection, 'nft_present_fields', unexpected_work)
    monkeypatch.setattr(nat, 'verify', unexpected_work)
    monkeypatch.setattr(nftables_zones, 'verify_zones', unexpected_work)

    configuration = ReadOnlyTree({'firewall': {'ipv4': {'forward': {'filter': {'rule': {
        '10': {'action': 'accept', 'source-address': {'192.0.2.1': {}}},
    }}}}}})

    firewall.verify(configuration, None)


def test_packet_only_group_skips_connection_entry_walk(monkeypatch):
    """Packet groups do not need a second pass over entries for conntrack."""
    monkeypatch.setattr(nftables_connection, 'verify_connection', unexpected_work)
    definition = {'match': {'source-address': {}}, 'entry': {
        'one': {'source-address': '192.0.2.1'},
    }}

    nftables_connection.verify_connection_group(definition, ('firewall', 'group'))


def test_connection_state_skips_absent_status_checks(monkeypatch):
    """Using one connection feature must not enter unrelated status validation."""
    monkeypatch.setattr(firewall, '_verify_offload_status', unexpected_work)

    firewall.verify_rule({'action': 'accept', 'connection': {'state': ['established']}}, RULE_PATH, {})


def test_negative_status_still_checks_offload_constraints():
    """A status exclusion remains subject to the same valid-combination checks."""
    rule = {'action': 'accept', 'connection': {'not': {'status': ['offload']}}}

    with pytest.raises(ValidationError, match='requires confirmed in the same group'):
        firewall.verify_rule(rule, RULE_PATH, {})


def test_connection_without_ports_skips_inherited_protocol_values(monkeypatch):
    """A conntrack protocol key alone does not need transport-port validation."""
    original = nftables_connection._inherited_values

    def inherited_values(definitions, field):
        if field == 'connection-protocol':
            raise AssertionError('Inspected protocol entries without a port match')
        return original(definitions, field)

    monkeypatch.setattr(nftables_connection, '_inherited_values', inherited_values)
    definition = {'match': {'connection': {'protocol': {}}}, 'entry': {
        'tcp': {'connection': {'protocol': 'tcp'}},
    }}

    nftables_connection.verify_connection({'action': 'accept'}, RULE_PATH, mapping=definition)


def test_address_learning_skips_inherited_protocol_values(monkeypatch):
    """Updating an address set does not need to inspect a verdict map's protocols."""
    monkeypatch.setattr(nftables, 'match_protocols', unexpected_work)
    groups = {'address-group': {'ipv4': {'learned': {'dynamic': {'timeout': '10m'}}}}}

    firewall.verify_group_update(
        {'action': 'accept', 'add-to-group': {'source-address': 'learned'}}, RULE_PATH, groups)


@pytest.mark.parametrize('feature,problem', [
    ('connection', 'connection requires at least one match, limit or timeout-group'),
    ('fib', 'fib'),
    ('limit', 'limit'),
    ('quota', 'quota'),
    ('add-to-group', 'add-to-group'),
])
def test_empty_features_still_enter_validation(feature, problem):
    """Empty configured branches are different from absent features."""
    configuration = ReadOnlyTree({'firewall': {'ipv4': {'forward': {'filter': {'rule': {
        '10': {'action': 'accept', feature: {}},
    }}}}}})

    with pytest.raises(ValidationError, match=problem):
        firewall.verify(configuration, None)


@pytest.mark.parametrize('source', ['mapping', 'match_group', 'excluded_group', 'update_group'])
def test_inherited_connection_fields_still_enter_validation(source):
    """All four sources of inherited fields must retain accounting validation."""
    definition = {'match': {'connection': {'total': {'bytes': {}}}}}

    with pytest.raises(ValidationError, match='require firewall global-options connection-accounting'):
        nftables_connection.verify_connection({'action': 'accept'}, RULE_PATH, **{source: definition})


def test_inherited_icmp_still_checks_explicit_conflicts():
    """An inherited type cannot hide a conflicting explicit transport header."""
    group = {'match': {'icmp-type': {}, 'protocol': {}}, 'entry': {
        'echo': {'icmp-type': 'echo-request', 'protocol': 'icmp'},
    }}

    with pytest.raises(ValidationError, match='ICMP matching cannot be combined with destination-port'):
        firewall.verify_rule(
            {'action': 'accept', 'match-group': 'echo', 'destination-port': ['22']},
            RULE_PATH, {}, match_groups={'echo': group})


@pytest.mark.parametrize('field', nftables_formatters.NFT_KEYMAP)
@pytest.mark.parametrize('negative', [False, True])
def test_field_discovery_retains_every_keymap_path(field, negative):
    """Empty selectors and nested exclusions must remain visible to all consumers."""
    key = nftables_formatters.NFT_KEYMAP[field]
    path = key.path or (field,)
    if negative:
        path = (*path[:-1], 'not', path[-1])

    configuration = {}
    branch = configuration
    for name in path:
        branch = branch.setdefault(name, {})

    assert nftables_formatters.nft_present_fields(ReadOnlyTree(configuration), negative=negative) == {field}
    assert nftables_formatters.nft_present_fields(ReadOnlyTree(configuration), negative=not negative) == set()


def test_field_discovery_ignores_unrelated_rule_branches(monkeypatch):
    """Discovery must not resume the previous full-keymap lookup for sparse rules."""
    monkeypatch.setattr(nftables_formatters, 'nft_field_value', unexpected_work)
    rule = ReadOnlyTree({
        'action': 'accept',
        'connection': {'original': {'not': {'destination-address': ['192.0.2.1']}}},
        'quota': {'group': 'download'},
    })

    assert nftables_formatters.nft_present_fields(rule) == set()
    assert nftables_formatters.nft_present_fields(rule, negative=True) == {'connection-original-destination-address'}


def test_group_fields_keep_canonical_order():
    """Faster discovery must not change concatenation order in generated nftables."""
    group = ReadOnlyTree({'match': {
        'destination-port': {}, 'protocol': {}, 'source-address': {},
    }})

    assert nftables_formatters.nft_group_fields(group) == ['source-address', 'protocol', 'destination-port']
