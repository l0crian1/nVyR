"""Keep configuration smoke checks separate from live behavior tests."""

import ast
import os
from pathlib import Path

from smoketests import assertions


ROOT = Path(__file__).resolve().parents[1]
pytest_plugins = ['pytester']


def test_smoketests_do_not_invoke_runtime_probes():
    """Packet, convergence and process-readiness helpers belong in functionaltests."""
    runtime_helpers = {
        'assert_bgp_path', 'assert_bgp_neighbor', 'assert_ping_reply',
        'assert_firewall_counter', 'assert_firewall_rule_packets',
        'assert_firewall_map_counter', 'assert_firewall_trace_capture',
        'assert_failsafe_lifecycle', 'assert_container_running',
        'assert_container_restarted', 'assert_dhcp_client', 'assert_dhcp_lease',
        'assert_dhcp_default_route', 'assert_dhcp_client_options',
        'assert_link_addresses', 'assert_ntp_configuration',
        'assert_ntp_serving_activity', 'assert_ntp_response', 'assert_ntp_vrf',
        'assert_probe_command',
    }
    for path in (ROOT / 'smoketests').glob('test_*.py'):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            name = ast.unparse(node.func)
            assert name not in runtime_helpers, (path.name, node.lineno, name)
            assert not name.startswith(('send_firewall_', 'send_ingress_')), (path.name, name)
            assert not name.endswith(('.sendto', '.sendall', '.recvfrom')), (path.name, name)
            if name in ('cmd', 'rc_cmd') and node.args and isinstance(node.args[0], ast.List):
                arguments = node.args[0].elts
                literals = [item.value for item in arguments if isinstance(item, ast.Constant)]
                assert not set(literals) & {'ping', 'traceroute'}, (path.name, literals)
                assert literals[:2] != ['podman', 'exec'], (path.name, literals)


def test_static_smoketests_check_frr_configuration_not_route_selection():
    """Resource collision/cleanup safeguards may inspect routes; feature checks target FRR."""
    source = ast.parse((ROOT / 'smoketests/test_static.py').read_text())
    for function in source.body:
        if not isinstance(function, ast.FunctionDef) or not function.name.startswith('test_'):
            continue
        for node in ast.walk(function):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                assert not name.startswith('assert_kernel_'), function.name
                assert name not in {'assert_route_present', 'assert_route_absent',
                                    'assert_no_static_routes'}, function.name


def test_native_configuration_assertions_do_not_probe_process_health(monkeypatch, tmp_path):
    """Chrony configuration and configured IPv6 addresses need no responsive process or carrier."""
    from nvyr.helpers import ntp

    configuration = tmp_path / 'chrony.conf'
    configuration.write_text('server 192.0.2.123 iburst\n')
    monkeypatch.setattr(ntp, 'CONFIGURATION', configuration)

    def unexpected_command(*args, **kwargs):
        raise AssertionError('Configuration inspection must not launch a health probe')

    monkeypatch.setattr(assertions, 'cmd', unexpected_command)
    assertions.assert_ntp_directives('server 192.0.2.123 iburst')


def test_both_suites_share_one_registration(pytester, monkeypatch):
    """Selecting both directories must not duplicate options, sessions or reporting."""
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join([str(ROOT), str(ROOT / 'src')]))
    for name in ('smoketests', 'functionaltests'):
        directory = pytester.mkdir(name)
        (directory / 'conftest.py').write_text((ROOT / name / 'conftest.py').read_text())
        (directory / f'test_{name}.py').write_text('''
def test_shared_options(request):
    assert request.config.getoption('--ethernet-interface') == 'eth1'
    assert request.config.getoption('--container-image') == 'alpine'
    assert request.config.pluginmanager.hasplugin('nvyr-live-fixtures')
''')

    result = pytester.runpytest_subprocess('smoketests', 'functionaltests',
                                         '--ethernet-interface', 'eth1', '--container-image', 'alpine')
    result.assert_outcomes(passed=2)


def test_both_live_suites_are_installed():
    """The functional suite needs the packaged shared smoke support as well as its tests."""
    script = (ROOT / 'scripts/build-deb.sh').read_text()
    assert 'for suite in smoketests functionaltests; do' in script
    assert '"$stage/usr/lib/nvyr/$suite/$relative"' in script

    assert (ROOT / 'functionaltests/network/test_bgp_policy.py').is_file()
    assert not (ROOT / 'smoketests/test_bgp_policy.py').exists()
    assert (ROOT / 'functionaltests/network/test_firewall_flowtable_packets.py').is_file()
    assert not (ROOT / 'smoketests/test_firewall_flowtable_packets.py').exists()
