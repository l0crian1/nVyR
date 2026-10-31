"""Opt-in real Netlink renames, isolated from the container/host interfaces."""

import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged naming container')


def test_real_netlink_name_swap_replacement_and_foreign_collision():
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    script = '''
from pathlib import Path
import socket, subprocess, tempfile
from nvyr.errors import RouterError
from nvyr.helpers.interface_names import Assignments, Coordinator, Port
def run(*argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
for name in ('eth0','eth1'):
    run('ip','link','add',name,'type','dummy')
ports = {socket.if_nametoindex('eth0'):'slotB', socket.if_nametoindex('eth1'):'slotA'}
released = set()
def inventory():
    return [Port(index,socket.if_indextoname(index),location,'/sys/devices/'+location,
                 managed=index in released) for index,location in ports.items()]
root = Path(tempfile.mkdtemp())
coordinator = Coordinator(Assignments(root/'names.json'),root/'ready',inventory=inventory,
                          release=lambda p:released.add(p.index))
assert not coordinator.reconcile()
assert coordinator.reconcile()
assert {socket.if_indextoname(index):value for index,value in ports.items()} == {'eth1':'slotB','eth0':'slotA'}
before = coordinator.assignments.read()
removed = socket.if_nametoindex('eth0')
run('ip','link','delete','eth0')
del ports[removed]
released.remove(removed)
run('ip','link','add','fresh0','type','dummy')
index = socket.if_nametoindex('fresh0')
ports[index] = 'slotA'
assert not coordinator.reconcile()
assert coordinator.reconcile()
assert socket.if_indextoname(index) == 'eth0' and coordinator.assignments.read() == before
run('ip','link','delete','eth0')
del ports[index]
run('ip','link','add','eth0','type','dummy') # unmanaged occupant
run('ip','link','add','fresh0','type','dummy')
ports[socket.if_nametoindex('fresh0')] = 'slotA'
try:
    coordinator.reconcile()
    raise AssertionError('Unmanaged interface name was stolen')
except RouterError as error:
    assert 'occupied' in str(error)
assert socket.if_nametoindex('fresh0')
'''
    result = subprocess.run(['unshare','-n',sys.executable,'-c',script],text=True,capture_output=True,timeout=30)

    assert result.returncode == 0, result.stdout + result.stderr


def test_failed_naming_blocks_netlinkd_and_configd_start():
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    def run(*args):
        return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()

    override = Path('/run/systemd/system/nvyr-interface-naming.service.d/99-test-failure.conf')

    assert not override.exists()

    override.parent.mkdir(parents=True, exist_ok=True)

    try:
        run('systemctl', 'stop', 'nvyr-interface-naming.service')
        override.write_text('[Service]\nExecStart=\nExecStart=/bin/false\nRestart=no\n')
        run('systemctl', 'daemon-reload')

        for service in ('nvyr-netlinkd.service', 'nvyr-configd.service'):
            failed = subprocess.run(['systemctl', 'start', service], capture_output=True, text=True)

            assert failed.returncode != 0, failed.stdout + failed.stderr
            assert run('systemctl', 'show', '--value', '-p', 'MainPID', service) == '0'
    finally:
        override.unlink(missing_ok=True)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'reset-failed', 'nvyr-interface-naming.service')
        run('systemctl', 'start', 'nvyr-configd.service')

        for service in ('nvyr-interface-naming.service', 'nvyr-netlinkd.service', 'nvyr-configd.service'):
            assert run('systemctl', 'is-active', service) == 'active'

        # Configd reports READY only after RPC startup and configuration recovery.
        deadline = time.monotonic() + 15

        while not Path('/run/nvyr/configd.sock').exists():
            assert time.monotonic() < deadline, 'configd did not recover after the naming failure test'

            time.sleep(.1)
