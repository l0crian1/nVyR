"""Execute the installed FRR Lua callback during an actual route installation.

This single case starts isolated daemons in a private namespace/pathspace. Its
custom scripting startup cannot share the router's managed FRR processes.
"""

import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import time

import pytest


if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from smoketests.assertions import assert_false, assert_in, assert_is_none, assert_less


def run(*arguments):
    """Run an isolated FRR or namespace command and retain failure diagnostics."""
    return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


def wait_for(predicate, description):
    """Allow daemon startup and asynchronous route installation to finish."""
    deadline = time.monotonic() + 15
    while not predicate():
        assert_less(time.monotonic(), deadline, msg=description() if callable(description) else description)
        time.sleep(0.05)


def test_lua_hook_executes_when_zebra_installs_route():
    """A real kernel route installation must invoke our Lua callback and log its prefix."""
    name = 'nvyr-lua-test'
    sockets = Path('/run/frr') / name
    assert_false(sockets.exists(), msg='test FRR pathspace is already occupied')
    assert_false((Path('/etc/frr') / name).exists(), msg='test FRR configuration path is already occupied')
    account = pwd.getpwnam('frr')
    processes = []
    logs = []
    run('ip', 'netns', 'add', name)
    try:
        run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        sockets.mkdir(mode=0o755)
        os.chown(sockets, account.pw_uid, account.pw_gid)
        with tempfile.TemporaryDirectory(prefix='nvyr-lua-', dir='/var/tmp') as temporary:
            work = Path(temporary)
            work.chmod(0o755)
            script = work / 'check.lua'
            script.write_text('function on_rib_process_dplane_results(ctx)\n'
                              '    log.info("NVYR-LUA-HOOK " .. ctx.rinfo.zd_dest.network)\n'
                              '    return {}\nend\n')
            try:
                for daemon in ('mgmtd', 'zebra', 'staticd'):
                    log = (work / (daemon + '.log')).open('w')
                    logs.append(log)
                    process = subprocess.Popen([
                        'ip', 'netns', 'exec', name, '/usr/lib/frr/' + daemon,
                        '-N', name, '--log', 'stdout',
                        '--scriptdir', str(work),
                    ], stdout=log, stderr=subprocess.STDOUT)
                    processes.append(process)
                    wait_for(lambda: (sockets / (daemon + '.vty')).exists() or process.poll() is not None,
                             lambda: f'{daemon} failed to start: {(work / (daemon + ".log")).read_text()}')
                    assert_is_none(process.poll(), msg=(work / (daemon + '.log')).read_text())

                run('vtysh', '-N', name, '-c', 'configure terminal',
                    '-c', 'zebra on-rib-process script check',
                    '-c', 'ip route 198.51.100.240/32 blackhole')
                wait_for(lambda: 'NVYR-LUA-HOOK 198.51.100.240' in (work / 'zebra.log').read_text(),
                         lambda: 'Zebra did not execute the Lua route callback: ' + (work / 'zebra.log').read_text())
                assert_in('198.51.100.240', run('ip', '-n', name, 'route', 'show'))
            finally:
                for process in reversed(processes):
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                for log in logs:
                    log.close()
    finally:
        run('ip', 'netns', 'del', name)
        if sockets.exists():
            for path in sockets.iterdir():
                path.unlink()
            sockets.rmdir()
