"""Standard-port helper selection, ordering and shared native object lifecycle."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import nftables_helpers as helpers
from nvyr.lexer import lex
from nvyr.schema import Schema
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


def configuration():
    """Enable each supported application and preserve an unrelated family chain."""
    return {'firewall': {
        'global-options': {'connection-tracking': {'helper': {'ftp': True, 'tftp': True, 'sip': True}}},
        'ipv4': {'name': {'UNCHANGED': {'default-action': 'drop'}}},
    }}


def test_helper_only_configuration_installs_three_hooks():
    """Helpers work without direct inet or family rules, and never create raw hooks."""
    text = rendered(configuration())
    assert 'chain input {' in text and 'chain forward {' in text and 'chain output {' in text
    assert 'chain prerouting {' not in text and 'chain output_raw {' not in text
    assert 'chain ipv4_input {' not in text
    assert text.count('ct helper set meta l4proto . th dport map @conntrack_helpers') == 3
    assert 'typeof meta l4proto . th dport : ct helper' in text
    assert 'tcp . 21 : "conntrack_helper_ftp_tcp"' in text
    assert 'udp . 69 : "conntrack_helper_tftp_udp"' in text
    assert 'tcp . 5060 : "conntrack_helper_sip_tcp"' in text
    assert 'udp . 5060 : "conntrack_helper_sip_udp"' in text
    assert text.count('l3proto inet') == 4


def test_assignment_follows_globals_and_precedes_user_rules():
    """Assignment neither bypasses global policies nor terminates rule evaluation."""
    tree = configuration()
    tree['firewall']['global-options']['state-policy'] = {'established': {'action': 'accept'}}
    tree['firewall']['inet'] = {'forward': {'filter': {'rule': {'10': {'action': 'drop'}}}}}
    tree['firewall']['ipv4']['forward'] = {'filter': {'default-action': 'drop'}}
    chain = rendered(tree).split('chain forward {', 1)[1]
    assert chain.index('ct state vmap') < chain.index('ct helper set') < chain.index('drop comment "10|"')
    assert chain.index('drop comment "10|"') < chain.index('meta nfproto vmap')
    assignment = helpers.assignment(tree['firewall'], 'forward')
    assert assignment.startswith('ct state new ct direction original meta l4proto { tcp, udp }')
    assert ' accept' not in assignment and ' return' not in assignment


def test_helper_removal_replaces_only_shared_consumers():
    """All map users release references in one transaction; family rules retain state."""
    before = configuration()
    after = deepcopy(before)
    del after['firewall']['global-options']['connection-tracking']['helper']['sip']
    text = rendered(after, before)
    assert destroyed(text, 'ct helper') == {'conntrack_helper_sip_tcp', 'conntrack_helper_sip_udp'}
    assert destroyed(text, 'map') == {'conntrack_helpers'}
    assert destroyed(text, 'chain') == {'input', 'forward', 'output'}
    assert 'ipv4_name_UNCHANGED' not in text
    assert text.index('flush chain') < text.index('destroy map') < text.index('destroy ct helper')
    assert 'ct helper conntrack_helper_ftp_tcp {' not in text
    assert 'tcp . 21 : "conntrack_helper_ftp_tcp"' in text


def test_last_helper_removal_removes_generated_hooks():
    """Deleting all helpers leaves no dangling map, object or helper-only chain."""
    text = rendered({}, configuration())
    assert destroyed(text, 'ct helper') == set(helpers.objects(configuration()['firewall']))
    assert destroyed(text, 'chain') >= {'input', 'forward', 'output'}
    assert 'ct helper set' not in text


def test_recovery_removes_unrecorded_helper_objects():
    """Recovery cleans fixed owned names even if the previous configuration is lost."""
    text = rendered({}, recovery=True)
    assert destroyed(text, 'ct helper') == set(helpers.objects(configuration()['firewall']))
    assert 'conntrack_helpers' in destroyed(text, 'map')


def test_unrelated_kernel_change_preserves_helpers():
    """Ordinary sysctl changes cannot reset the shared helper map or its users."""
    before = configuration()
    after = deepcopy(before)
    after['firewall']['global-options']['connection-tracking']['timeout'] = {'udp': {'stream': '4m'}}
    assert not destroyed(rendered(after, before), 'ct helper')
    assert not destroyed(rendered(after, before), 'map')


def test_helper_selection_requires_a_supported_application():
    """Empty parents and invalid direct verify calls fail with a meaningful error."""
    with pytest.raises(RouterError, match='select at least one helper'):
        rendered({'firewall': {'global-options': {'connection-tracking': {'helper': {}}}}})
    with pytest.raises(RouterError, match='invalid helper'):
        helpers.verify({'unknown': True})
    with pytest.raises(RouterError, match='invalid helper'):
        helpers.verify({'ftp': False})


def test_helpers_anchor_and_are_excluded_from_fail_safe(controller, session):
    """Valueless siblings can be entered together, but early firewall exposes none."""
    controller.execute('set firewall global-options connection-tracking helper ftp tftp sip', session)
    schema = Schema.bundled()
    cursor = schema.resolve(lex('firewall fail-safe global-options'))
    assert 'connection-tracking' not in cursor.node['children']
