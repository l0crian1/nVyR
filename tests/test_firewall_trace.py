"""Trace rendering, operational dispatch, bounded capture and file protection."""

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from nvyr.helpers import access
from nvyr.errors import OperationalError, RouterError
from nvyr.helpers import firewall_trace as trace
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall_trace, ping, traceroute
from tests.test_firewall_maps import rendered


EVENT = 'trace id 12ab inet nvyr_filter ipv4_input rule meta nftrace set 1 accept comment "10|SSH" (verdict accept)'


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
@pytest.mark.parametrize('hook,stage', [('input', 'filter'), ('forward', 'filter'), ('output', 'filter'),
                                       ('prerouting', 'raw'), ('output', 'raw'), ('ingress', 'filter')])
def test_trace_is_after_matches_before_verdict(family, hook, stage):
    """All supported firewall hooks share a nonterminal trace statement."""
    chain = {'rule': {'10': {'protocol': ['tcp'], 'destination-port': ['22'],
                             'nftrace': True, 'action': 'accept'}}}
    if hook == 'ingress':
        chain['interface'] = ['eth1']
    text = rendered({'firewall': {family: {hook: {stage: chain}}}})
    line = next(line for line in text.splitlines() if 'comment "10|' in line)
    assert line.index('th dport') < line.index('meta nftrace set 1') < line.index('accept')


def test_trace_normalizes_for_operational_detail():
    """The new statement must not turn an otherwise supported rule into raw data."""
    document = {'nftables': [{'table': {'family': 'inet', 'name': 'nvyr_filter'}},
        {'chain': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv4_input'}},
        {'rule': {'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ipv4_input',
                  'handle': 3, 'comment': '10|SSH', 'expr': [
                      {'mangle': {'key': {'meta': {'key': 'nftrace'}}, 'value': 1}}, {'accept': None}]}}]}
    rule = normalize(document)['tables']['inet']['nvyr_filter']['chains']['ipv4_input']['rules'][0]
    assert rule['nftrace'] is True
    assert 'unsupported' not in rule


def test_cli_dispatch_and_permissions(controller, session, engine, monkeypatch):
    """Anchored options work in either order and only administrators can capture."""
    controller.execute('set firewall ipv4 input filter rule 10 action accept nftrace', session)
    assert engine.view(session)['firewall']['ipv4']['input']['filter']['rule']['10']['nftrace'] is True
    line = 'monitor firewall trace save /config/traces/test.jsonl duration 2m'
    event = controller.execute(line)
    assert event['argv'] == ['firewall_trace.nvyr.op', 'monitor', line]
    assert event['timeout'] is None
    received = {}
    monkeypatch.setattr(trace, 'monitor', lambda **kw: received.update(kw) or 0)
    with pytest.raises(SystemExit) as result:
        firewall_trace.monitor('run ' + line)
    assert result.value.code == 0
    assert received == {'duration': 120, 'save': '/config/traces/test.jsonl'}
    for suffix in ('duration 0s', 'duration 2', 'save /etc/passwd', 'save /config/traces/../oops'):
        with pytest.raises(RouterError):
            controller.execute('monitor firewall trace ' + suffix)
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError):
            controller.execute(line)
    finally:
        access.role.reset(token)


@pytest.mark.parametrize('module,command', [(ping, 'ping'), (traceroute, 'traceroute')])
def test_probe_vrf_options(module, command, controller):
    """VRF binding wraps the whole utility, preserving its own interface/source flags."""
    line = f'{command} example.com vrf BLUE interface eth1 source-address 192.0.2.1'
    argv = module._argv(line)
    assert argv[:5] == ['ip', 'vrf', 'exec', 'BLUE', command]
    assert argv[-2:] == ['--', 'example.com']
    assert 'eth1' in argv and '192.0.2.1' in argv
    assert module._argv(f'{command} ::1 ipv6 vrf default')[:4] == ['ip', 'vrf', 'exec', 'default']
    assert controller.execute(line)['argv'][-1] == line
    candidates = dict(controller.completion(f'{command} 127.0.0.1 vrf ', explicit=True)['candidates'])
    assert 'default' in candidates


def test_event_paths_and_unknown_events():
    """Native details survive parsing; comments identify ordinary, named and NAT rules."""
    record = trace.event_record(EVENT)
    assert record['path'] == 'firewall ipv4 input filter rule 10'
    assert record['id'] == '12ab' and record['raw'] == EVENT
    assert trace.rule_path('nvyr_filter', 'forward', '20|') == 'firewall inet forward filter rule 20'
    assert trace.rule_path('nvyr_filter_failsafe', 'ipv6_name_SSH', '10|') == 'firewall fail-safe ipv6 name SSH rule 10'
    assert trace.rule_path('nvyr_filter', 'ipv4_nat_prerouting', '30|') == 'nat destination rule 30'
    assert trace.rule_path('foreign', 'ipv4_input', '10|') is None
    assert trace.event_record('unrecognized native event')['raw'] == 'unrecognized native event'


def test_timed_capture_and_no_overwrite(tmp_path, monkeypatch):
    """A quiet stream still reaches its deadline and a complete JSONL event is flushed."""
    directory = tmp_path / 'traces'
    monkeypatch.setattr(trace, 'DIRECTORY', directory)
    target = directory / 'capture.jsonl'
    child = 'import time; print(' + repr(EVENT) + ',flush=True); time.sleep(30)'
    output = []
    started = time.monotonic()
    assert trace.monitor(duration=.5, save=str(target), arguments=[sys.executable, '-c', child],
                         output=lambda text, **kw: output.append(text)) == 0
    assert time.monotonic() - started < 4
    records = [json.loads(line) for line in target.read_text().splitlines()]
    assert records[0]['event'] == 'capture'
    assert records[1]['raw'] == EVENT
    assert records[-1]['event'] == 'capture-end'
    assert target.stat().st_mode & 0o777 == 0o600
    assert 'Captured 1 trace events.' in output
    with pytest.raises(OperationalError, match='File exists'):
        trace.monitor(duration=.1, save=str(target), output=lambda *args, **kw: None)
    assert [json.loads(line) for line in target.read_text().splitlines()][1]['raw'] == EVENT


def test_capture_rejects_symlink_directory(tmp_path, monkeypatch):
    """The privileged capture cannot follow a user-controlled directory redirect."""
    outside = tmp_path / 'outside'
    outside.mkdir()
    directory = tmp_path / 'traces'
    directory.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(trace, 'DIRECTORY', directory)
    with pytest.raises(OperationalError):
        trace.monitor(duration=.1, save=str(directory / 'capture.jsonl'), output=lambda *args, **kw: None)
    assert not list(outside.iterdir())


def test_native_failure_and_quiet_timeout():
    """Native monitor errors remain errors; an idle deadline is successful."""
    with pytest.raises(OperationalError, match='Permission denied'):
        trace.monitor(arguments=[sys.executable, '-c', 'import sys; sys.stderr.write("Permission denied"); sys.exit(1)'],
                      output=lambda *args, **kw: None)
    assert trace.monitor(duration=.05, arguments=[sys.executable, '-c', 'import time; time.sleep(30)'],
                         output=lambda *args, **kw: None) == 0


def test_cancellation_reaps_monitor(tmp_path):
    """Ctrl+C retains flushed events, reports cancellation, and does not orphan nft."""
    pid_file = tmp_path / 'child.pid'
    child = f'import os,time; open({str(pid_file)!r},"w").write(str(os.getpid())); time.sleep(30)'
    script = ('from nvyr.helpers.firewall_trace import monitor; '
              f'raise SystemExit(monitor(arguments={[sys.executable, "-c", child]!r}))')
    process = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        assert pid_file.exists()
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 130, stderr
        assert b'Captured 0 trace events.' in stdout
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
