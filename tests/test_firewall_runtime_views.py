"""Installed limit keys and quota usage, scoped to chains and individual rules."""

from copy import deepcopy
import json

import pytest

from nvyr.errors import OperationalError
from nvyr.helpers import access
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall


def listing():
    """A native listing containing private, shared, inline and connection allowances."""
    base = {'family': 'inet', 'table': 'nvyr_filter'}
    source = {'payload': {'protocol': 'ip', 'field': 'saddr'}}
    port = {'payload': {'protocol': 'tcp', 'field': 'dport'}}
    rate = {'rate': 10, 'per': 'second', 'burst': 5}
    return {'nftables': [
        {'chain': {**base, 'name': 'ipv4_input'}},
        {'set': {**base, 'name': 'rule_limit_ipv4_input_10', 'type': ['ipv4_addr', 'inet_service'],
                 'size': 65536, 'flags': ['dynamic', 'timeout'], 'timeout': 60,
                 'elem': [{'elem': {'val': {'concat': ['192.0.2.10', 22]}, 'expires': 52,
                                    'limit': rate}}]}},
        {'set': {**base, 'name': 'rule_connection_limit_ipv4_input_10', 'type': 'ipv4_addr',
                 'size': 100, 'flags': ['dynamic'], 'elem': ['192.0.2.10']}},
        {'rule': {**base, 'chain': 'ipv4_input', 'comment': '10|', 'expr': [
            {'set': {'op': 'update', 'set': '@rule_limit_ipv4_input_10',
                     'elem': {'concat': [source, port]}, 'stmt': [{'limit': rate}]}},
            {'set': {'op': 'add', 'set': '@rule_connection_limit_ipv4_input_10',
                     'elem': source, 'stmt': [{'ct count': {'val': 5, 'inv': True}}]}},
            {'accept': None}]}},
        {'rule': {**base, 'chain': 'ipv4_input', 'comment': '20|', 'expr': [
            {'quota': {'val': 1, 'val_unit': 'kbytes', 'used': 2048, 'inv': True}}, {'drop': None}]}},
        {'quota': {**base, 'name': 'quota_group_SHARED', 'bytes': 10 * 1024 ** 3,
                   'used': 3 * 1024 ** 3}},
        {'rule': {**base, 'chain': 'ipv4_input', 'comment': '30|', 'expr': [
            {'quota': 'quota_group_SHARED'}, {'accept': None}]}},
        {'limit': {**base, 'name': 'ipv4_limit_group_GLOBAL', **rate}},
        {'rule': {**base, 'chain': 'ipv4_input', 'comment': '40|', 'expr': [
            {'limit': 'ipv4_limit_group_GLOBAL'}, {'accept': None}]}},
        {'set': {**base, 'name': 'ipv4_limit_group_KEYED', 'type': 'ipv4_addr', 'size': 200,
                 'flags': ['timeout', 'dynamic'], 'timeout': 60, 'elem': []}},
        {'rule': {**base, 'chain': 'ipv4_input', 'comment': '50|', 'expr': [
            {'set': {'op': 'update', 'set': '@ipv4_limit_group_KEYED', 'elem': source,
                     'stmt': [{'limit': rate}]}}, {'accept': None}]}},
        {'rule': {**base, 'chain': 'ipv4_input', 'comment': '60|', 'expr': [
            {'limit': rate}, {'accept': None}]}},
        {'rule': {**base, 'chain': 'ipv4_input', 'comment': '70|', 'expr': [{'accept': None}]}},
        {'rule': {**base, 'chain': 'ipv4_input', 'comment': 'default|', 'expr': [{'accept': None}]}},
    ]}


@pytest.fixture
def installed(monkeypatch):
    table = normalize(listing())['tables']['inet']['nvyr_filter']
    monkeypatch.setattr(firewall, '_load_table', lambda **kwargs: table)
    return table


def test_private_rate_and_connection_keys(installed, capsys):
    """Fields come from the installed expression, and connection keys have no fake expiry."""
    firewall.runtime('limit', 'ipv4', hook='input', stage='filter', rule='10')
    text = capsys.readouterr().out
    assert 'Rule 10 rate limit' in text and 'Rule 10 connection limit' in text
    assert 'Source address' in text and 'Destination port' in text
    assert '192.0.2.10' in text and '52s' in text and '65536' in text
    assert 'Expires' not in text.split('Rule 10 connection limit')[1]
    assert 'rule_limit_' not in text
    assert 'default' not in text


def test_raw_state_and_private_masking(installed, capsys):
    """Raw counts remain integers and address masking never changes normalized data."""
    before = deepcopy(installed)
    data = json.loads(firewall.runtime('limit', 'ipv4', hook='input', rule='10', raw=True))
    rate, connection = data[0]['records']
    assert rate['entries'][0]['key'] == ['192.0.2.10', 22]
    assert rate['entries'][0]['expires'] == 52
    assert rate['active-keys'] == 1 and rate['capacity'] == 65536
    assert 'timeout' not in connection

    firewall.runtime('limit', 'ipv4', hook='input', rule='10', strip_private=True)
    text = capsys.readouterr().out
    assert '192.0.2.10' not in text and '<ipv4>' in text
    assert installed == before


def test_shared_and_non_keyed_limits(installed, capsys):
    """Shared objects use installed parameters, including when no keys exist yet."""
    firewall.runtime('limit', 'ipv4', hook='input')
    text = capsys.readouterr().out
    assert 'Group (shared)' in text and 'GLOBAL' in text and 'KEYED' in text
    assert 'No active keys recorded.' in text
    assert 'no per-key entries' in text
    data = json.loads(firewall.runtime('limit', 'ipv4', hook='input', rule='50', raw=True))
    assert data[0]['records'][0]['parameters']['rate'] == {'packets': '10/s'}
    assert data[0]['records'][0]['entries'] == []


def test_quota_remaining_and_shared_usage(installed, capsys):
    """Used bytes may exceed allowance; remaining never goes negative."""
    firewall.runtime('quota', 'ipv4', hook='input')
    text = capsys.readouterr().out
    assert 'Group (shared)' in text and 'SHARED' in text
    assert '10 GiB' in text and '3 GiB' in text and '7 GiB' in text
    assert 'over' in text and '0 B' in text
    data = json.loads(firewall.runtime('quota', 'ipv4', hook='input', rule='20', raw=True))
    assert data[0]['records'] == [{'rule': '20', 'mode': 'over', 'bytes': 1024,
                                   'used': 2048, 'remaining': 0}]
    assert firewall._bytes(0) == '0 B'


def test_missing_state_is_not_zero_usage(installed):
    """A dangling reference must fail, rather than pretend an allowance is untouched."""
    del installed['sets']['rule_limit_ipv4_input_10']
    with pytest.raises(OperationalError, match='Cannot read installed'):
        firewall.runtime('limit', 'ipv4', hook='input', rule='10')
    del installed['quotas']['quota_group_SHARED']
    with pytest.raises(OperationalError, match='Cannot read installed'):
        firewall.runtime('quota', 'ipv4', hook='input', rule='30')


def test_empty_missing_and_unsupported_rules(installed, capsys):
    """Distinguish no allowance, missing rule, and unsupported installed expressions."""
    firewall.runtime('limit', 'ipv4', hook='input', rule='70')
    assert 'No limits installed' in capsys.readouterr().out
    with pytest.raises(OperationalError, match='Rule 999 is not installed'):
        firewall.runtime('quota', 'ipv4', hook='input', rule='999')
    with pytest.raises(OperationalError, match='not installed'):
        firewall.runtime('quota', 'ipv4', named=True, chain_name='MISSING')
    installed['chains']['ipv4_input']['rules'][-2]['unsupported'] = [{'reason': 'unknown'}]
    firewall.runtime('limit', 'ipv4', hook='input', rule='70')
    assert 'display is incomplete' in capsys.readouterr().out


def test_named_ipv6_and_prefix_columns(installed, capsys):
    """Named chains retain family scope and subnet keys disclose their prefix length."""
    chain = installed['chains'].pop('ipv4_input')
    chain['name'] = 'ipv6_name_POLICY'
    installed['chains']['ipv6_name_POLICY'] = chain
    rate = chain['rules'][0]['runtime-limits']['limit']
    rate['source-prefix-length'] = 64
    installed['sets'][rate['set']]['entries'][0]['key'][0] = '2001:db8::'
    firewall.runtime('limit', 'ipv6', named=True, chain_name='POLICY', rule='10')
    text = capsys.readouterr().out
    assert 'IPv6 name POLICY' in text and 'Source address (/64)' in text
    assert '2001:db8::' in text
    assert json.loads(firewall.runtime('limit', 'ipv4', raw=True)) == []


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('scope,arguments', [
    ('input filter', ['--hook', 'input', '--stage', 'filter']),
    ('forward filter', ['--hook', 'forward', '--stage', 'filter']),
    ('output filter', ['--hook', 'output', '--stage', 'filter']),
    ('output raw', ['--hook', 'output', '--stage', 'raw']),
    ('prerouting raw', ['--hook', 'prerouting', '--stage', 'raw']),
    ('name POLICY', ['--named', '--chain_name', 'POLICY']),
])
@pytest.mark.parametrize('kind', ['limit', 'quota'])
def test_plural_chain_singular_rule_dispatch(controller, monkeypatch, family, scope, arguments, kind):
    """Every installed chain scope exposes plural collections and singular rule children."""
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'state\n')
    token = access.role.set('read-only')
    try:
        assert controller.execute(f'show firewall {family} {scope} {kind}s')['text'] == 'state\n'
        assert controller.execute(f'show firewall {family} {scope} rule 10 {kind}')['text'] == 'state\n'
    finally:
        access.role.reset(token)
    base = ['firewall.nvyr.op', 'runtime', kind, '--family', family, *arguments]
    assert calls == [base, [*base, '--rule', '10']]
    completion = controller.completion(f'show firewall {family} {scope} rule 10 ', explicit=True)
    assert {'limit', 'quota'} <= dict(completion['candidates']).keys()
