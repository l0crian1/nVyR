"""Read-only system displays on the installed router; no configuration changes."""

from contextlib import closing
import json
import os

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.helpers.process import cmd
from nvyr.helpers import build_metadata
from nvyr.protocol import Client
from smoketests.assertions import (
    assert_diagnostic_archive, assert_equal, assert_in, assert_true, assert_operational_output,
)


def test_version_identity():
    """Installed version output includes image metadata and attribution without headers."""
    metadata = build_metadata.read()
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show version')['text']

    rows = [line.split('|', 1) for line in output.splitlines()]
    assert_equal([label.strip() for label, value in rows],
                 ['Version', 'Build date', 'Built by', 'Copyright', 'Project'])
    assert_equal(rows[0][1].strip(), metadata['version'])
    assert_equal(rows[2][1].strip(), metadata.get('built_by') or 'Not specified')
    assert_in(build_metadata.COPYRIGHT, output)
    assert_in(build_metadata.PROJECT_URL, output)


def test_installed_license():
    """The operational command exposes the packaged MIT text through the usual pipeline."""
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show license | no-more')['text']

    assert_equal(output, build_metadata.read_license())
    assert_in('MIT License', output)
    assert_in(build_metadata.COPYRIGHT, output)


def test_package_inventory():
    """The packaged script and CLI both expose installed versions and exact selection."""
    records = json.loads(cmd(['system.nvyr.op', 'packages', '--name', 'nvyr-router', '--raw']))
    assert_equal(len(records), 1)
    assert_equal(records[0]['package'], 'nvyr-router')
    assert_true(bool(records[0]['version']))

    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show system packages | no-more')['text']
        selected = client.request('execute', text='show system packages nvyr-router')['text']

    assert_in('Architecture', output)
    assert_in('nvyr-router', output)
    assert_in(records[0]['version'], selected)


def test_configuration_script_priorities():
    """The installed command reads its packaged inventory and lists only declaring paths."""
    records = json.loads(cmd(['system.nvyr.op', 'script_priority', '--raw']))
    assert_true(bool(records))
    assert_equal(records, sorted(records, key=lambda record: (record['priority'], record['script'])))
    firewall = next(record for record in records if record['script'] == 'firewall')
    assert_in('firewall', firewall['paths'])
    assert_true('firewall ipv4 forward filter rule <name>' not in firewall['paths'])

    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show system config script-priority')['text']
    assert_in('Script', output)
    assert_in('Priority', output)
    assert_in('Paths', output)


def test_active_login_display():
    """The installed command reads session accounting even when no terminal is logged in."""
    records = json.loads(cmd(['users.nvyr.op', 'show', '--raw']))
    assert_true(isinstance(records, list))
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show users')['text']
    assert_in('User' if records else 'No users logged in.', output)

    # Only an actual login terminal has a row to mark; API/non-TTY calls have none.
    try:
        terminal = os.ttyname(0).removeprefix('/dev/')
    except OSError:
        terminal = None
    if any(record['terminal'] == terminal for record in records):
        assert_in('(this session)', output)


def test_service_summary():
    """The public command includes the configuration, interface and routing daemons."""
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show system services')['text']
    assert_in('configd', output)
    assert_in('netlinkd', output)
    assert_in('frr', output)
    assert_in('Uptime', output)


def test_configuration_service_detail():
    """A running router reports the real daemon PID and process uptime in a scoped view."""
    records = json.loads(cmd(['services.nvyr.op', 'show', '--service', 'configd', '--raw']))
    assert_equal(len(records), 1)
    assert_equal(records[0]['state'], 'Running')
    assert_true(records[0]['pid'] > 0)
    assert_true(records[0]['uptime_seconds'] >= 0)
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show system services configd detail')['text']
    assert_in(' | ', output)
    assert_in('Restarts', output)


def test_storage_usage():
    """Report real mounts including the writable root, with space and inode columns."""
    records = json.loads(cmd(['system.nvyr.op', 'storage', '--raw']))
    assert_true(any(item['target'] == '/' for item in records))
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show system storage')['text']
    assert_in('Available', output)
    assert_in('Inode %', output)


def test_process_inventory():
    """The normal process view includes kernel PIDs and executable names without argv."""
    records = json.loads(cmd(['system.nvyr.op', 'processes', '--raw']))
    assert_true(any(item['pid'] == 1 for item in records))
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show system processes')['text']
    assert_in('Resident', output)
    assert_in('CPU % (lifetime)', output)


def test_process_cpu_sort():
    """The CPU selector orders lifetime averages from highest to lowest."""
    records = json.loads(cmd(['system.nvyr.op', 'processes', '--sort', 'cpu', '--raw']))
    usage = [item['cpu_percent'] for item in records]
    assert_equal(usage, sorted(usage, reverse=True))
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show system processes cpu')['text']
    assert_in('CPU % (lifetime)', output)


def test_process_memory_sort():
    """The memory selector orders resident bytes rather than formatted size strings."""
    records = json.loads(cmd(['system.nvyr.op', 'processes', '--sort', 'memory', '--raw']))
    usage = [item['resident_bytes'] for item in records]
    assert_equal(usage, sorted(usage, reverse=True))
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show system processes memory')['text']
    assert_in('Resident', output)


def test_diagnostic_snapshot():
    """Run the installed host worker and check its private, bounded archive, then remove it."""
    output = cmd(['diagnostics.nvyr.op', 'generate'], timeout=85)
    assert_diagnostic_archive(output)


def test_date_display():
    """The public command executes the installed date program and produces a timestamp."""
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show date')['text']
    assert_true(output.strip())
    assert_in(':', output)


def test_uptime_display():
    """Use the real CLI path to the system uptime command."""
    assert_operational_output('show system uptime', 'up', 'load average')


def test_cpu_summary():
    """Check the installed lscpu mapping, not a synthetic topology fixture."""
    assert_operational_output('show system cpu', 'Architecture', 'Cores', 'Threads')


def test_cpu_usage():
    """Sample real CPU accounting through the public operational command."""
    assert_operational_output('show system cpu usage', 'Total', 'Idle %', 'System %')


def test_memory_display():
    """The installed free utility supplies memory totals through configd dispatch."""
    assert_operational_output('show system memory', 'Mem:', 'Swap:')
