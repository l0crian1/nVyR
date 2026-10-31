"""Static route operational dispatch, native output, and internal JSON mode."""

import pytest

from nvyr import opmode
from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.op_scripts import static


@pytest.mark.parametrize('line,words', [
    ('show ip route', ('show', 'ip', 'route')),
    ('show ipv6 route', ('show', 'ipv6', 'route')),
    ('show ip route bgp', ('show', 'ip', 'route', 'bgp')),
    ('show ipv6 route bgp', ('show', 'ipv6', 'route', 'bgp')),
    ('show ip route connected', ('show', 'ip', 'route', 'connected')),
    ('show ipv6 route connected', ('show', 'ipv6', 'route', 'connected')),
    ('show ip route kernel', ('show', 'ip', 'route', 'kernel')),
    ('show ipv6 route kernel', ('show', 'ipv6', 'route', 'kernel')),
    ('show ip route local', ('show', 'ip', 'route', 'local')),
    ('show ipv6 route local', ('show', 'ipv6', 'route', 'local')),
    ('show ip route tag 42', ('show', 'ip', 'route', 'tag', '42')),
    ('show ipv6 route tag 42', ('show', 'ipv6', 'route', 'tag', '42')),
    ('show ip route vrf BLUE bgp', ('show', 'ip', 'route', 'vrf', 'BLUE', 'bgp')),
    ('show ipv6 route table 254 local', ('show', 'ipv6', 'route', 'table', '254', 'local')),
    ('show ip route static', ('show', 'ip', 'route', 'static')),
    ('show ipv6 route static failed', ('show', 'ipv6', 'route', 'static', 'failed')),
    ('show ip route summary prefix', ('show', 'ip', 'route', 'summary', 'prefix')),
    ('show ipv6 route summary table 254 prefix', ('show', 'ipv6', 'route', 'summary', 'table', '254', 'prefix')),
    ('show ip route vrf BLUE static', ('show', 'ip', 'route', 'vrf', 'BLUE', 'static')),
    ('show ipv6 route vrf all summary', ('show', 'ipv6', 'route', 'vrf', 'all', 'summary')),
    ('show ip route table 254 static', ('show', 'ip', 'route', 'table', '254', 'static')),
    ('show ip route 192.0.2.1', ('show', 'ip', 'route', '192.0.2.1')),
    ('show ip route 192.0.2.0/24', ('show', 'ip', 'route', '192.0.2.0/24')),
    ('show ipv6 route vrf BLUE 2001:db8::/32', ('show', 'ipv6', 'route', 'vrf', 'BLUE', '2001:db8::/32')),
    ('show ip route vrf BLUE 192.0.2.0/24', ('show', 'ip', 'route', 'vrf', 'BLUE', '192.0.2.0/24')),
    ('show ip route 192.0.2.0/24 longer-prefixes static',
     ('show', 'ip', 'route', '192.0.2.0/24', 'longer-prefixes', 'static')),
    ('run sho ipv6 rou table 254 2001:db8::/32', ('show', 'ipv6', 'route', 'table', '254', '2001:db8::/32')),
    ('show static routes', ('show', 'static', 'routes')),
    ('show static routes vrf default', ('show', 'static', 'routes', 'vrf', 'default')),
    ('show static routes vrf BLUE', ('show', 'static', 'routes', 'vrf', 'BLUE')),
    ('run sho sta rou vr BLUE | count', ('show', 'static', 'routes', 'vrf', 'BLUE')),
])
@pytest.mark.parametrize('raw', [False, True])
def test_wrapper_canonicalizes_commands_and_passes_raw(monkeypatch, line, words, raw):
    calls = []
    output = '{"default": {"routes": []}}\n' if raw else 'VRF default:\n'

    def show(arguments, *, raw=False):
        calls.append((arguments, raw))
        return output

    monkeypatch.setattr(static.vtysh, 'show', show)

    assert static.show(line, raw=raw) == output
    assert calls == [(words, raw)]


@pytest.mark.parametrize('line', [
    '', 'configure', 'show version', 'show static', 'show static routes vrf',
    'show static routes json', 'show ip route raw', 'show static routes vrf "BLUE\nexit"',
    'show ip route vrf', 'show ip route table 0', 'show ipv6 route table 4294967296',
    'show ip route 2001:db8::/32', 'show ipv6 route vrf BLUE 192.0.2.0/24',
    'show ip route destination 192.0.2.0/24',
    'show ip route 192.0.2.0/24 vrf BLUE', 'show ip route 192.0.2.1 longer-prefixes',
    'show ip route tag', 'show ipv6 route tag 0', 'show ip route tag 4294967296',
])
def test_wrapper_rejects_incomplete_or_unrelated_commands(monkeypatch, line):
    monkeypatch.setattr(static.vtysh, 'show', lambda *args, **kwargs: pytest.fail('Invalid command executed'))

    with pytest.raises(RouterError):
        static.show(line)


@pytest.mark.parametrize('line', [
    'show ip route', 'show ipv6 route', 'show static routes', 'show static routes vrf BLUE',
    'show ip route vrf BLUE 192.0.2.0/24', 'show ipv6 route 2001:db8::/32',
])
def test_dispatch_preserves_line_in_both_modes(controller, session, monkeypatch, line):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'route output\n')

    for prefix, mode in [('', None), ('run ', session)]:
        result = controller.execute(prefix + line, mode)
        assert calls[-1] == ['static.nvyr.op', 'show', prefix + line]
        assert result['text'] == 'route output\n'


def test_operator_can_read_routes_but_json_is_not_a_cli_command(controller, monkeypatch):
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: 'routes\n')

    role = access.role.set('read-only')
    try:
        assert controller.execute('show static routes')['text'] == 'routes\n'
    finally:
        access.role.reset(role)

    for line in ['show static routes json', 'show static routes raw', 'show ip route json']:
        with pytest.raises(RouterError):
            controller.execute(line)


def test_completion_includes_static_routes_and_vrfs(controller):
    candidates = dict(controller.completion('show static ', explicit=True)['candidates'])
    assert 'routes' in candidates

    candidates = dict(controller.completion('show static routes ', explicit=True)['candidates'])
    assert {'<Enter>', 'vrf'} <= candidates.keys()
    assert 'json' not in candidates

    candidates = dict(controller.completion('show static routes vrf ', explicit=True)['candidates'])
    assert 'default' in candidates


def test_native_text_still_supports_output_pipes(controller, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'S>* 192.0.2.0/24\nC>* 198.51.100.0/24\n')

    result = controller.execute('show ip route | match "S>"')
    assert result['text'].strip() == 'S>* 192.0.2.0/24'
    assert calls == [['static.nvyr.op', 'show', 'show ip route']]


def test_prefix_hints_and_completion_follow_vrf(controller):
    help = controller.completion('show ip route vrf BLUE ', explicit=True)
    assert 'x.x.x.x/x' in dict(help['hints'])
    assert 'destination' not in dict(help['candidates'])
    assert {'static', 'summary', '<Enter>'} <= dict(help['candidates']).keys()

    help = controller.completion('show ipv6 route vrf BLUE 2001:db8::/32 ', explicit=True)
    assert {'longer-prefixes', '<Enter>'} <= dict(help['candidates']).keys()


def test_internal_raw_option_prints_json_through_opmode(monkeypatch, capsys):
    calls = []

    def show(words, *, raw=False):
        calls.append((words, raw))
        return '{"default": {"routes": []}}'

    monkeypatch.setattr(static.vtysh, 'show', show)
    opmode.run(['show', 'show static routes', '--raw'], namespace=vars(static))

    assert calls == [(('show', 'static', 'routes'), True)]
    assert capsys.readouterr().out == '{"default": {"routes": []}}\n'


def test_invalid_command_reports_an_error_without_a_traceback(monkeypatch, capsys):
    monkeypatch.setattr(static.vtysh, 'show', lambda *args, **kwargs: pytest.fail('Invalid command executed'))

    with pytest.raises(SystemExit) as result:
        opmode.run(['show', 'show ip route vrf BLUE invalid'], namespace=vars(static))

    assert result.value.code == 1
    error = capsys.readouterr().err
    assert 'Invalid value' in error
    assert 'Traceback' not in error
