"""Opt-in kernel hook lifecycle checks; run inside a disposable kernel-test VM."""

import os
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_KERNEL_TEST') != '1',
                                reason='requires root in a disposable VM with the candidate kernel')


def test_prefix_hooks_follow_device_creation_rename_and_deletion():
    """Keep one flowtable installed while devices enter and leave its native prefix."""
    assert os.geteuid() == 0
    script = '''
import json
import subprocess

def run(*arguments):
    return subprocess.check_output(arguments, text=True)

def hook_count(device):
    listing = run('nft', 'list', 'hooks', 'netdev', 'device', device)
    return listing.count('flowtable inet kernel_test fast')

run('nft', 'add', 'table', 'inet', 'kernel_test')
run('nft', 'add', 'flowtable', 'inet', 'kernel_test', 'fast',
    '{ hook ingress priority 0; devices = { "nvft*" }; }')
before = run('nft', '-j', '-a', 'list', 'flowtable', 'inet', 'kernel_test', 'fast')

# Device creation must attach the hook without another nftables transaction.
run('ip', 'link', 'add', 'nvft0', 'type', 'veth', 'peer', 'name', 'peer0')
assert hook_count('nvft0') == 1
assert hook_count('peer0') == 0

# Renaming out of the prefix removes the hook, and renaming into it adds one.
run('ip', 'link', 'set', 'nvft0', 'name', 'outside0')
assert hook_count('outside0') == 0
run('ip', 'link', 'set', 'outside0', 'name', 'nvft1')
assert hook_count('nvft1') == 1

# Deletion and recreation must not retain a stale ifindex or duplicate hook.
run('ip', 'link', 'delete', 'nvft1')
run('ip', 'link', 'add', 'nvft1', 'type', 'veth', 'peer', 'name', 'peer1')
assert hook_count('nvft1') == 1
after = run('nft', '-j', '-a', 'list', 'flowtable', 'inet', 'kernel_test', 'fast')
original = next(item['flowtable'] for item in json.loads(before)['nftables'] if 'flowtable' in item)
current = next(item['flowtable'] for item in json.loads(after)['nftables'] if 'flowtable' in item)
assert original['handle'] == current['handle']
assert current['dev'] == original['dev']

# Removing the table must unregister hooks from every still-matching interface.
run('nft', 'delete', 'table', 'inet', 'kernel_test')
assert hook_count('nvft1') == 0
'''
    result = subprocess.run(['unshare', '-n', sys.executable, '-c', script],
                            capture_output=True, text=True, timeout=30)

    assert result.returncode == 0, result.stdout + result.stderr


def test_exact_hook_follows_future_device_creation_and_recreation():
    """An absent exact name registers later without replacing its flowtable."""
    assert os.geteuid() == 0
    script = '''
import json
import subprocess

def run(*arguments):
    return subprocess.check_output(arguments, text=True)

def hook_count():
    listing = run('nft', 'list', 'hooks', 'netdev', 'device', 'nvft0')
    return listing.count('flowtable inet kernel_test fast')

def flowtable():
    listing = run('nft', '-j', '-a', 'list', 'flowtable', 'inet', 'kernel_test', 'fast')
    return next(item['flowtable'] for item in json.loads(listing)['nftables'] if 'flowtable' in item)

# Install the flowtable before its exact interface exists.
run('nft', 'add', 'table', 'inet', 'kernel_test')
run('nft', 'add', 'flowtable', 'inet', 'kernel_test', 'fast',
    '{ hook ingress priority 0; devices = { "nvft0" }; }')
original = flowtable()

# Link creation and recreation must attach one hook without reloading nftables.
run('ip', 'link', 'add', 'nvft0', 'type', 'veth', 'peer', 'name', 'peer0')
assert hook_count() == 1
run('ip', 'link', 'delete', 'nvft0')
run('ip', 'link', 'add', 'nvft0', 'type', 'veth', 'peer', 'name', 'peer0')
assert hook_count() == 1
current = flowtable()
assert original['handle'] == current['handle']
assert original['dev'] == current['dev']

# Table removal must unregister the remaining hook.
run('nft', 'delete', 'table', 'inet', 'kernel_test')
assert hook_count() == 0
'''
    result = subprocess.run(['unshare', '-n', sys.executable, '-c', script],
                            capture_output=True, text=True, timeout=30)

    assert result.returncode == 0, result.stdout + result.stderr
