"""Run with NVYR_VRF_RULE_TEST=1 inside a disposable network namespace."""

import os
from pathlib import Path
import subprocess

import pytest

from nvyr.helpers.netlink import Kernel, TYPES

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_VRF_RULE_TEST') != '1',
                                reason='requires an isolated root network namespace')


def run(*arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


@pytest.fixture
def routing():
    """Exercise the production VRF driver without altering the router namespace."""
    assert os.geteuid() == 0
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
    kernel = Kernel()
    run('ip', 'link', 'set', 'lo', 'up')

    try:
        with kernel.snapshot():
            for name, table in (('BLUE', 101), ('RED', 102)):
                spec = {'name': name, 'attributes': {'table': table}}
                TYPES['vrf'].create(kernel, spec)
                kernel.refresh(name)
                TYPES['vrf'].configure(kernel, spec, {})
                kernel.state(name, True)

        run('ip', 'link', 'add', 'left', 'type', 'veth', 'peer', 'name', 'right')
        run('ip', 'link', 'set', 'right', 'master', 'BLUE')
        run('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'left')
        run('ip', 'address', 'add', '192.0.2.2/24', 'dev', 'right')
        run('ip', '-6', 'address', 'add', '2001:db8::1/64', 'dev', 'left', 'nodad')
        run('ip', '-6', 'address', 'add', '2001:db8::2/64', 'dev', 'right', 'nodad')
        run('ip', 'link', 'set', 'left', 'up')
        run('ip', 'link', 'set', 'right', 'up')

        for name in ('all', 'left', 'right', 'BLUE', 'RED'):
            Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').write_text('0')
        yield kernel
    finally:
        for name in ('left', 'BLUE', 'RED'):
            subprocess.run(['ip', 'link', 'del', name], capture_output=True)
        kernel.close()


def test_ipv4_default_and_named_vrf_connectivity(routing):
    """Both directions cross the cable, including after moving into a second VRF."""
    run('ping', '-I', 'left', '-c', '2', '-W', '2', '192.0.2.2')
    run('ip', 'vrf', 'exec', 'BLUE', 'ping', '-c', '2', '-W', '2', '192.0.2.1')

    run('ip', 'link', 'set', 'left', 'master', 'RED')
    run('ip', 'vrf', 'exec', 'RED', 'ping', '-c', '2', '-W', '2', '192.0.2.2')
    run('ip', 'vrf', 'exec', 'BLUE', 'ping', '-c', '2', '-W', '2', '192.0.2.1')


def test_ipv6_default_and_named_vrf_connectivity(routing):
    """IPv6 uses the same routing order and preserves VRF-local delivery."""
    run('ping', '-6', '-I', 'left', '-c', '2', '-W', '2', '2001:db8::2')
    run('ip', 'vrf', 'exec', 'BLUE', 'ping', '-6', '-c', '2', '-W', '2', '2001:db8::1')

    run('ip', 'link', 'set', 'left', 'master', 'RED')
    # Linux can remove IPv6 addresses on a master change; netlinkd reasserts them.
    run('ip', '-6', 'address', 'replace', '2001:db8::1/64', 'dev', 'left', 'nodad')
    run('ip', 'vrf', 'exec', 'RED', 'ping', '-6', '-c', '2', '-W', '2', '2001:db8::2')
    run('ip', 'vrf', 'exec', 'BLUE', 'ping', '-6', '-c', '2', '-W', '2', '2001:db8::1')


def test_ipv4_no_fallback_to_main_or_default_local(routing):
    """A valid main-table route and default-local address remain inaccessible from BLUE."""
    run('ip', 'route', 'add', '198.51.100.0/24', 'dev', 'left')
    run('ip', 'address', 'add', '203.0.113.1/32', 'dev', 'left')
    run('ip', 'route', 'get', '198.51.100.1')
    run('ping', '-c', '1', '-W', '2', '203.0.113.1')

    for address in ('198.51.100.1', '203.0.113.1'):
        result = subprocess.run(['ip', 'route', 'get', address, 'vrf', 'BLUE'], capture_output=True, text=True)
        assert result.returncode != 0 and 'unreachable' in result.stderr.lower()


def test_ipv6_no_fallback_to_main_or_default_local(routing):
    """The no-fallback guard also covers IPv6 routes and default-local addresses."""
    run('ip', '-6', 'route', 'add', '2001:db8:1::/64', 'dev', 'left')
    run('ip', '-6', 'address', 'add', '2001:db8:2::1/128', 'dev', 'left', 'nodad')
    run('ip', '-6', 'route', 'get', '2001:db8:1::1')
    run('ping', '-6', '-c', '1', '-W', '2', '2001:db8:2::1')

    for address in ('2001:db8:1::1', '2001:db8:2::1'):
        result = subprocess.run(['ip', '-6', 'route', 'get', address, 'vrf', 'BLUE'], capture_output=True, text=True)
        assert result.returncode != 0 and 'unreachable' in result.stderr.lower()


def test_rule_repair_and_restart(routing):
    """A new backend repairs missing rules and does not create duplicate entries."""
    run('ip', '-6', 'rule', 'del', 'pref', '2000', 'l3mdev', 'unreachable')
    run('ip', 'rule', 'add', 'pref', '0', 'lookup', 'local')
    restarted = Kernel()

    try:
        with restarted.snapshot():
            TYPES['vrf'].configure(restarted, {'name': 'BLUE', 'attributes': {'table': 101}}, {})
        before = run('ip', 'rule'), run('ip', '-6', 'rule')
        with restarted.snapshot():
            restarted.vrf_rules()
        assert before == (run('ip', 'rule'), run('ip', '-6', 'rule'))
        assert not before[0].startswith('0:')
        assert '2000:' in before[1] and 'unreachable' in before[1]
    finally:
        restarted.close()
