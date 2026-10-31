"""Exercise real sysfs rename/removal races in private network/mount namespaces."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get('NVYR_RECOVERY_TEST') != '1',
    reason='requires explicit root access for isolated network/mount namespaces',
)

PROBE = r'''
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

source, scenario = sys.argv[1:]
spec = importlib.util.spec_from_file_location('naming_probe', source)
naming = importlib.util.module_from_spec(spec)
spec.loader.exec_module(naming)

subprocess.run(['mount', '--make-rprivate', '/'], check=True)
subprocess.run(['mount', '-t', 'sysfs', 'sysfs', '/sys'], check=True)
subprocess.run(['ip', 'link', 'add', 'raceold0', 'type', 'dummy'], check=True)
old = Path('/sys/class/net/raceold0').resolve()
new = old.with_name('racenew0')
scans = []

def paths():
    scans.append(True)

    if len(scans) == 1:
        if scenario == 'before-open':
            subprocess.run(['ip', 'link', 'set', 'raceold0', 'name', 'racenew0'], check=True)
        elif scenario == 'unplug':
            subprocess.run(['ip', 'link', 'delete', 'raceold0'], check=True)

        yield old
    elif scenario != 'unplug':
        yield new

# A disposable dummy models a physical link changing names without touching any
# real port. Keep real sysfs, event writes, coldplug and the startup serving loop.
naming.physical_paths = paths
original_open = Path.open

def rename_after_open(path, *args, **kwargs):
    stream = original_open(path, *args, **kwargs)

    if scenario == 'after-open' and path == old / 'uevent' and args == ('w',):
        subprocess.run(['ip', 'link', 'set', 'raceold0', 'name', 'racenew0'], check=True)

    return stream

Path.open = rename_after_open
events = []
trigger = naming.trigger_change

def observed_trigger(path):
    try:
        trigger(path)
    except OSError:
        events.append('failed')
        raise

    events.append('delivered')

naming.trigger_change = observed_trigger
notices = []

class Ready(Exception):
    pass

def notify(message):
    notices.append(message)

    if message.startswith('READY=1'):
        raise Ready

naming.notify = notify

with tempfile.TemporaryDirectory(prefix='nvyr-coldplug-') as directory:
    root = Path(directory)

    try:
        naming.serve(root / 'state.json', root / 'ready', 5)
    except Ready:
        pass
    else:
        raise AssertionError('Naming returned without readiness')

if scenario == 'before-open':
    assert events == ['failed', 'delivered'], events
    assert new.exists() and not old.exists()
elif scenario == 'after-open':
    assert events == ['delivered'], events
    assert new.exists() and not old.exists()
elif scenario == 'unplug':
    assert events == ['failed'], events
    assert not old.exists()

assert notices[-1].startswith('READY=1'), notices
print(scenario + ': reached READY in the original process; ' + str(events))
'''


def run_probe(scenario):
    """Use real kernel links while protecting the host's network and sysfs mount."""
    assert os.geteuid() == 0
    repository = Path(__file__).resolve().parents[1]
    source = repository / 'src/nvyr/interface_naming.py'
    result = subprocess.run(
        ['unshare', '-nm', sys.executable, '-c', PROBE, str(source), scenario],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_real_rename_before_event_open_rescans_without_process_restart():
    """Reproduce the boot failure window before opening the sysfs event file."""
    run_probe('before-open')


def test_real_rename_after_event_open_delivers_to_same_device():
    """An open sysfs event descriptor remains valid across a kernel rename."""
    run_probe('after-open')


def test_real_hot_unplug_during_discovery_does_not_block_readiness():
    """A fresh inventory drops removed devices instead of retrying stale paths."""
    run_probe('unplug')
