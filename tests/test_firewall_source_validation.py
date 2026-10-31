"""Source validation shares raw chains, defaults and whole-object lifecycle handling."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import nftables_source_validation as source_validation
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall as display
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


def configuration(family='ipv4', default='strict'):
    """Return a global policy with enabled and disabled interface exceptions."""
    alternate = 'strict' if default == 'loose' else 'loose'
    return {'firewall': {family: {'source-validation': {
        'default': default,
        'interface': {'eth1': {'mode': alternate}, 'eth2': {'mode': 'disabled'}},
    }}}}


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
def test_source_validation_schema_anchoring_and_hints(controller, engine, session, family):
    """Both anchor levels accept readable commands and expose meaningful choices."""
    controller.execute(f'set firewall {family} source-validation default loose interface eth1 mode strict', session)
    controller.execute(f'set firewall {family} source-validation interface eth2 mode disabled', session)
    options = engine.view(session)['firewall'][family]['source-validation']
    assert options['default'] == 'loose'
    assert options['interface']['eth1']['mode'] == 'strict'
    assert options['interface']['eth2']['mode'] == 'disabled'

    completion = controller.completion(f'set firewall {family} source-validation default ', session, explicit=True)
    assert {'strict', 'loose', 'disabled'} <= dict(completion['candidates']).keys()
    with pytest.raises(RouterError):
        controller.execute(f'set firewall {family} source-validation interface eth* mode strict', session)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
@pytest.mark.parametrize('default', ['strict', 'loose'])
def test_source_validation_creates_raw_chain_and_two_disjoint_checks(family, default):
    """Validation alone creates dispatch and never terminates successful packets."""
    tree = configuration(family, default)
    original = deepcopy(tree)
    text = rendered(tree)
    name = source_validation.chain_name(family)
    alternate = 'strict' if default == 'loose' else 'loose'
    assert f'chain {name} {{' in text
    assert 'type filter hook prerouting priority raw' in text
    assert f'set source_validation_{family}_overrides' in text
    assert 'elements = { "eth1", "eth2" }' in text
    assert f'iifname @source_validation_{family}_{alternate}' in text
    assert f'iifname != @source_validation_{family}_overrides' in text
    assert text.count('counter drop comment "source-validation-') == 2
    assert 'fib saddr . iif oif 0' in text
    assert 'fib saddr oif 0' in text
    assert tree == original


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
def test_source_validation_precedes_user_raw_rules(family):
    """An accept in the same raw chain cannot bypass its validation checks."""
    tree = configuration(family)
    tree['firewall'][family]['prerouting'] = {'raw': {'rule': {'10': {'action': 'accept'}}}}
    text = rendered(tree)
    assert text.index('counter drop comment "source-validation-') < text.index('accept comment "10|"')


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
def test_implicit_disabled_default_only_checks_enabled_interfaces(family):
    """Without a global mode, each enabled override has a positive interface set."""
    tree = {'firewall': {family: {'source-validation': {'interface': {
        'eth1': {'mode': 'strict'}, 'eth2': {'mode': 'loose'},
    }}}}}
    text = rendered(tree)
    assert 'iifname !=' not in text
    assert text.count('counter drop comment "source-validation-') == 2
    assert f'iifname @source_validation_{family}_strict' in text
    assert f'iifname @source_validation_{family}_loose' in text

    assert 'chain prerouting' not in rendered({'firewall': {family: {'source-validation': {}}}})


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_inet_and_ip_source_validation_are_exclusive_even_when_disabled(family):
    """Presence of both scopes is rejected rather than silently selecting one."""
    tree = {'firewall': {'inet': {'source-validation': {}}, family: {'source-validation': {}}}}
    with pytest.raises(RouterError, match='cannot be combined'):
        rendered(tree)


def test_both_ip_families_can_have_independent_defaults():
    """Independent IPv4/IPv6 policy produces one validation rule in each chain."""
    tree = {'firewall': {
        'ipv4': {'source-validation': {'default': 'strict'}},
        'ipv6': {'source-validation': {'default': 'loose'}},
    }}
    text = rendered(tree)
    assert 'ipv4 : jump ipv4_prerouting' in text
    assert 'ipv6 : jump ipv6_prerouting' in text
    assert text.count('counter drop comment "source-validation-') == 2
    assert 'set source_validation' not in text


@pytest.mark.parametrize('mode', ['strict', 'loose', 'disabled'])
def test_redundant_interface_override_is_rejected(mode):
    """Every explicit interface mode must differ from the effective default."""
    options = {'default': mode, 'interface': {'eth1': {'mode': mode}}}
    with pytest.raises(RouterError, match=f'mode {mode} matches the global default'):
        rendered({'firewall': {'ipv4': {'source-validation': options}}})


def test_missing_mode_and_implicit_disabled_override_are_rejected():
    """Bare interface nodes and redundant disabled overrides cannot commit."""
    with pytest.raises(RouterError, match='mode is required'):
        rendered({'firewall': {'ipv4': {'source-validation': {'interface': {'eth1': {}}}}}})
    with pytest.raises(RouterError, match='matches the global default'):
        rendered({'firewall': {'ipv4': {'source-validation': {'interface': {'eth1': {'mode': 'disabled'}}}}}})


def test_override_changes_replace_sets_and_consuming_chain_only():
    """Private sets and their consumers change together, preserving unrelated counters."""
    before = configuration()
    before['firewall']['ipv4']['input'] = {'filter': {'rule': {'10': {'action': 'accept', 'counter': {}}}}}
    after = deepcopy(before)
    after['firewall']['ipv4']['source-validation']['interface']['eth1']['mode'] = 'disabled'
    text = rendered(after, before)
    assert destroyed(text) == {'ipv4_prerouting', 'prerouting'}
    assert 'destroy set inet nvyr_filter source_validation_ipv4_loose' in text
    assert 'set source_validation_ipv4_loose {' not in text
    assert 'set source_validation_ipv4_overrides {' in text
    assert 'chain ipv4_input {' not in text
    assert 'source_validation' not in rendered(after, after)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
def test_global_only_mode_change_and_removal_rebuild_raw_chain(family):
    """A sibling setting must rebuild raw even when no native sets exist."""
    before = {'firewall': {family: {
        'source-validation': {'default': 'strict'},
        'prerouting': {'raw': {'rule': {'10': {'action': 'continue'}}}},
    }}}
    after = deepcopy(before)
    after['firewall'][family]['source-validation']['default'] = 'loose'
    text = rendered(after, before)
    assert source_validation.chain_name(family) in destroyed(text)
    assert 'fib saddr oif 0 counter drop' in text
    assert 'fib saddr . iif' not in text

    del after['firewall'][family]['source-validation']
    text = rendered(after, before)
    assert source_validation.chain_name(family) in destroyed(text)
    assert 'source-validation-strict|' not in text
    assert 'continue comment "10|"' in text


def test_vrf_changes_refresh_exclusions_without_firewall_edits():
    """Master names join the same exclusion set and trigger whole-chain replacement."""
    before = configuration()
    after = deepcopy(before)
    after['vrf'] = {'name': {'BLUE': {'table': '100'}}}
    text = rendered(after, before)
    assert destroyed(text) == {'ipv4_prerouting', 'prerouting'}
    assert 'elements = { "BLUE", "eth1", "eth2" }' in text
    assert 'set source_validation_ipv4_loose {' not in text
    assert 'meta iifkind' not in text and 'meta sdif' not in text

    removed = rendered(before, after)
    assert 'elements = { "eth1", "eth2" }' in removed
    assert '"BLUE"' not in removed


def test_vrf_device_cannot_be_an_explicit_ingress_override():
    """The user's override must select a real member rather than a second-pass master."""
    tree = {'vrf': {'name': {'BLUE': {'table': '100'}}}, 'firewall': {
        'inet': {'source-validation': {'interface': {'BLUE': {'mode': 'strict'}}}},
    }}
    with pytest.raises(RouterError, match='select a VRF member interface'):
        rendered(tree)


def test_vrf_watch_runs_firewall_after_vrf_creation(controller, engine, session):
    """Schema watches handle VRF creation/removal without bespoke interface callbacks."""
    controller.execute('set firewall inet source-validation default strict', session)
    assert engine.commit(session)['results']['firewall']['success']

    controller.execute('set vrf name BLUE table 100', session)
    results = engine.commit(session)['results']
    assert results['firewall']['success']
    assert list(results).index('vrf') < list(results).index('firewall')

    controller.execute('delete vrf name BLUE', session)
    assert engine.commit(session)['results']['firewall']['success']


def test_failsafe_source_validation_uses_its_own_table(tmp_path):
    """The same code renders early protection with future VRF/interface names."""
    from nvyr.config_scripts import firewall_failsafe
    from tests.test_firewall_failsafe import context

    tree = {'firewall': {'fail-safe': configuration()['firewall']},
            'vrf': {'name': {'BLUE': {'table': '100'}}}}
    ctx = context(tree, tmp_path, recovery=True)
    scoped = firewall_failsafe.get_config(ctx)
    firewall_failsafe.verify(scoped, ctx)
    text = firewall_failsafe.generate(scoped, ctx)
    assert 'table inet nvyr_filter_failsafe {' in text
    assert 'elements = { "BLUE", "eth1", "eth2" }' in text
    assert text.count('counter drop comment "source-validation-') == 2


def test_display_resolves_private_sets_and_keeps_partial_listings(capsys):
    """Drops appear in raw output with counters and understandable interface detail."""
    rule = {'rule': {'family': 'inet', 'table': 'nvyr_filter', 'chain': 'prerouting',
        'comment': 'source-validation-strict|Strict source validation (default)', 'expr': [
            {'match': {'left': {'meta': {'key': 'iifname'}}, 'op': '!=', 'right': '@source_validation_inet_overrides'}},
            {'match': {'left': {'fib': {'result': 'oif', 'flags': ['saddr', 'iif']}}, 'op': '==', 'right': '0'}},
            {'counter': {'packets': 3, 'bytes': 300}}, {'drop': None},
        ]}}
    group = {'set': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'source_validation_inet_overrides',
                     'type': 'ifname', 'elem': ['eth1', 'eth2']}}
    table = normalize({'nftables': [rule, group]})['tables']['inet']['nvyr_filter']
    installed = table['chains']['prerouting']['rules'][0]
    assert installed['not']['inbound-interface'] == ['eth1', 'eth2']
    assert 'unsupported' not in installed
    assert installed['counter']['packets'] == 3
    sections = list(display._chains(table, 'inet', 'prerouting', 'raw', False, None))
    assert len(sections) == 1
    display._show_chain(sections[0][0], sections[0][1], None, False, False)
    assert 'source-validation-strict' in capsys.readouterr().out

    partial = normalize({'nftables': [rule]})['tables']['inet']['nvyr_filter']['chains']['prerouting']['rules'][0]
    assert partial['not']['source-validation-interface-set'] == 'source_validation_inet_overrides'
    assert 'unsupported' not in partial
