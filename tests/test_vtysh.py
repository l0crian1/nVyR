"""Shared vtysh output preserves native text and exposes validated JSON."""

import pytest

from nvyr.helpers import vtysh
from nvyr.helpers.process import CommandError


def test_text_preserves_frr_formatting(monkeypatch):
    calls = []
    output = 'Codes: S - static\n\nS>* 192.0.2.0/24 [1/0] blackhole\n'
    monkeypatch.setattr(vtysh, 'cmd', lambda argv: calls.append(argv) or output)

    assert vtysh.show(['show', 'ip', 'route', 'static']) == output
    assert calls == [['vtysh', '-c', 'show ip route static']]


def test_raw_selects_json_without_changing_its_structure(monkeypatch):
    calls = []
    output = '{"default": {"routes": []}}\n'
    monkeypatch.setattr(vtysh, 'cmd', lambda argv: calls.append(argv) or output)

    assert vtysh.show(['show', 'static', 'routes'], raw=True) == output
    assert calls == [['vtysh', '-c', 'show static routes json']]


@pytest.mark.parametrize('output', ['', 'Unknown command', "{'routes': []}", '{}\n{}\n'])
def test_raw_rejects_non_json_output(monkeypatch, output):
    monkeypatch.setattr(vtysh, 'cmd', lambda argv: output)

    with pytest.raises(CommandError, match='FRR did not return valid JSON'):
        vtysh.show(['show', 'static', 'routes'], raw=True)


def test_frr_failures_remain_errors(monkeypatch):
    def failed(argv):
        raise CommandError('staticd is not running')

    monkeypatch.setattr(vtysh, 'cmd', failed)
    with pytest.raises(CommandError, match='staticd is not running'):
        vtysh.show(['show', 'static', 'routes'])


@pytest.mark.parametrize('words', [
    [], ['configure', 'terminal'], ['show', 'ip\nconfigure terminal'],
    ['show', 'ip;configure'], ['show', 'ip\x00'], ['show', '"ip"'],
    ['show', 'ip', None],
])
def test_commands_cannot_embed_additional_vty_or_shell_input(monkeypatch, words):
    monkeypatch.setattr(vtysh, 'cmd', lambda argv: pytest.fail('Unsafe command executed'))

    with pytest.raises(ValueError, match='single FRR show command'):
        vtysh.show(words)


def test_clear_passes_literal_star_without_shell_expansion(monkeypatch):
    calls = []
    monkeypatch.setattr(vtysh, 'cmd', lambda argv: calls.append(argv) or '')
    assert vtysh.clear(('clear', 'bgp', 'vrf', 'BLUE', '*', 'soft', 'in')) == ''
    assert calls == [['vtysh', '-c', 'clear bgp vrf BLUE * soft in']]


@pytest.mark.parametrize('words', [
    [], ['clear', 'bgp'], ['clear', 'ip', 'route'], ['show', 'bgp', 'summary'],
    ['clear', 'bgp', '*\nconfigure terminal'], ['clear', 'bgp', '192.0.2.2;exit'],
    ['clear', 'bgp', None], ['clear', 'bgp', '192.0.2.*'],
    ['clear', 'route-map'], ['clear', 'route-map', 'counters', '*'],
    ['clear', 'route-map', 'counters', 'IMPORT;exit'],
    ['clear', 'route-map', 'counters', 'IMPORT\nconfigure terminal'],
    ['clear', 'route-map', 'counters', 'IMPORT', 'extra'],
])
def test_clear_rejects_other_commands_and_embedded_input(monkeypatch, words):
    monkeypatch.setattr(vtysh, 'cmd', lambda argv: pytest.fail('Unsafe reset executed'))
    with pytest.raises(ValueError, match='single FRR clear bgp or clear route-map counters command'):
        vtysh.clear(words)


def test_clear_route_map_all_or_named(monkeypatch):
    calls = []
    monkeypatch.setattr(vtysh, 'cmd', lambda argv: calls.append(argv) or '')

    vtysh.clear(('clear', 'route-map', 'counters'))
    vtysh.clear(('clear', 'route-map', 'counters', 'IMPORT'))

    assert calls == [['vtysh', '-c', 'clear route-map counters'],
                     ['vtysh', '-c', 'clear route-map counters IMPORT']]
