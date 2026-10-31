"""Installed NAT summaries retain native order, targets and optional tracking."""

import json
from pathlib import Path

import pytest

from nvyr.errors import OperationalError
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall, nat


@pytest.fixture
def installed(monkeypatch):
    document = json.loads((Path(__file__).parent / 'fixtures/nftables/listings.json').read_text())['ruleset']
    table = normalize(document)['tables']['inet']['nvyr_filter']
    monkeypatch.setattr(firewall, '_load_table', lambda **kwargs: table)
    return table


def test_installed_nat_targets_preserve_order(installed, capsys):
    rules = json.loads(nat.show(direction='destination', raw=True))
    assert [rule['number'] for rule in rules] == ['1', '2', '3', '5', '6', '4']
    nat.show(direction='destination')
    output = capsys.readouterr().out
    assert 'Destination NAT' in output
    assert 'map NAT' in output and 'masquerade' in output and 'exclude' in output
    assert '10.0.0.1-10.0.0.10' in output and '1000-2000' in output
    assert 'Packets' in output and 'Bytes' in output
    assert output.index('map NAT') < output.index('masquerade') < output.index('exclude')


def test_rule_detail_shows_match_fields_and_translation(installed, capsys):
    nat.show(direction='destination', rule='2', detail=True)
    output = capsys.readouterr().out
    assert 'Rule 2' in output and 'Rule 3' not in output
    assert ' | ' in output and 'Translation' in output and '10.0.0.1-10.0.0.10' in output


def test_missing_nat_chain_and_rule(installed, capsys):
    nat.show(direction='source')
    assert 'No rules installed.' in capsys.readouterr().out
    with pytest.raises(OperationalError, match='not installed'):
        nat.show(direction='source', rule='10')


def test_counter_absence_and_unsupported_expression(installed, capsys):
    rule = installed['chains']['ipv4_nat_prerouting']['rules'][0]
    rule['counter'] = {'packets': 0, 'bytes': 0}
    rule['unsupported'] = [{'unsupported-native-expression': {}}]
    nat.show(direction='destination', rule='1')
    output = capsys.readouterr().out
    assert '[incomplete]' in output and 'Warning:' in output
    assert json.loads(nat.show(direction='destination', rule='1', raw=True))[0]['counter']['packets'] == 0
