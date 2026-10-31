"""Opt-in daemon RSS/object profiling, using only temporary dummy interfaces.

sudo env PYTHONPATH=src python3 tests/netlink_memory_benchmark.py --count 1000 --host-dummies
Omit --host-dummies to require a fresh namespace containing only lo.
--trace enables tracemalloc (which increases RSS); --diagnostics also measures
explicit cyclic collection and libc trimming, without changing daemon policy.
Never run two copies at once. No installed daemon, DHCP client or resolver is changed.
"""

import argparse
import gc
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc


def serve(root, trace):
    if trace:
        tracemalloc.start()

    from nvyr.helpers.dhcp import DHCP
    from nvyr.helpers.interfaces import NetlinkManager
    from nvyr.helpers.link_manager import Manager
    from nvyr.helpers.netlink import Kernel
    from nvyr.netlink_daemon import Server

    kernel = Kernel()
    manager = Manager(kernel, DHCP(root/'runtime'), root/'state')
    server = Server(manager, root/'control.sock')
    ready = threading.Event()
    thread = threading.Thread(target=lambda: server.run(ready=ready.set))
    thread.start()

    try:
        assert ready.wait(10)

        print('ready', flush=True)

        for line in sys.stdin:
            command = line.strip()
            if command == 'stop':
                break

            collected = gc.collect() if command == 'collect' else None

            if command == 'trim':
                import ctypes

                libc = ctypes.CDLL(None)
                libc.malloc_trim.argtypes = [ctypes.c_size_t]
                libc.malloc_trim.restype = ctypes.c_int
                libc.malloc_trim(0)

            rss = next(line for line in Path('/proc/self/status').read_text().splitlines()
                       if line.startswith('VmRSS:'))
            result = {
                'rss_kib': int(rss.split()[1]), 'collected': collected,
                'state': {key: len(manager.state[key]) for key in ('records', 'pending')},
                'indexes': {key: len(getattr(manager, key)) for key in
                            ('claims', 'indices', 'observed', 'dependents', 'failures', 'dhcp_names')},
                'kernel_cache': {key: None if getattr(kernel, key) is None else len(getattr(kernel, key))
                                 for key in ('_links', '_addresses', '_routes', '_expected', '_stale_addresses')},
                'checkpoint_bytes': manager.path.stat().st_size,
                'wal_bytes': manager.updates.stat().st_size,
                'gc_stats': gc.get_stats(),
            }

            if trace:
                result['traced_current_bytes'], result['traced_peak_bytes'] = tracemalloc.get_traced_memory()
                result['profiler_bytes'] = tracemalloc.get_tracemalloc_memory()

                if command == 'collect':
                    snapshot = tracemalloc.take_snapshot()
                    result['top_allocations'] = [str(entry) for entry in snapshot.statistics('lineno')[:15]]
                    del snapshot

            print(json.dumps(result), flush=True)

            if command == 'collect':
                sys._debugmallocstats()  # Diagnostic allocator inventory on stderr.
    finally:
        server.running = False

        if thread.is_alive() and server.path.exists():
            try:
                NetlinkManager(server.path).request('status')  # Wake the selector.
            except Exception:
                pass

        thread.join(10)

        assert not thread.is_alive()

        kernel.close()


def benchmark(args):
    from nvyr.helpers.interfaces import NetlinkManager

    if os.geteuid() != 0 or args.count < 1 or args.cycles < 1:
        raise SystemExit('Run as root with positive --count and --cycles')

    before = {name for _, name in socket.if_nameindex()}
    if not args.host_dummies and before != {'lo'}:
        raise SystemExit('Use a fresh namespace or explicitly select --host-dummies')

    names = {f'dum{880000+i}' for i in range(args.count)}
    if names & before:
        raise SystemExit('Benchmark interface names already exist; no changes made')

    root = Path(tempfile.mkdtemp(prefix='nvyr-memory-'))
    print(f'Benchmark journal (retained on failure): {root}', file=sys.stderr, flush=True)
    client = NetlinkManager(root/'control.sock')

    def start():
        argv = [sys.executable, '-u', str(Path(__file__).resolve()), '--serve', str(root)]

        if args.trace:
            argv.append('--trace')

        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        if child.stdout.readline().strip() != 'ready':
            child.wait(timeout=15)
            raise RuntimeError('Benchmark daemon did not start')

        return child

    def sample(stage, command='sample'):
        child.stdin.write(command+'\n')
        child.stdin.flush()
        result = json.loads(child.stdout.readline())
        print(json.dumps(dict(result, stage=stage, count=args.count)), flush=True)

    def replace(links):
        started = time.monotonic()
        client.request('replace', owner='memory-benchmark', links=links)
        print(json.dumps({'operation': 'replace', 'links': len(links),
                          'seconds': time.monotonic()-started}), flush=True)

    def stop():
        child.stdin.write('stop\n')
        child.stdin.flush()
        child.wait(timeout=15)
        child.stdin.close()
        child.stdout.close()

    child = start()

    try:
        time.sleep(2)
        sample('before')

        for cycle in range(args.cycles):
            replace({name: {'kind': 'dummy'} for name in sorted(names)})
            time.sleep(2)
            sample(f'created-{cycle}')
            replace({})
            time.sleep(2)
            sample(f'deleted-{cycle}')

            if args.diagnostics:
                sample(f'collected-{cycle}', 'collect')
                sample(f'trimmed-{cycle}', 'trim')

        stop()
        child = start()  # Same journal, new process.
        time.sleep(2)
        sample('restarted')
    finally:
        try:
            if child.poll() is None:
                client.request('replace', owner='memory-benchmark', links={}, recovery=True)
        finally:
            if child.poll() is None:
                stop()

    after = {name for _, name in socket.if_nameindex()}

    assert before <= after and not names & after, 'Unexpected interface inventory after cleanup'

    shutil.rmtree(root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--count', type=int, default=1000)
    parser.add_argument('--cycles', type=int, default=1)
    parser.add_argument('--host-dummies', action='store_true')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--diagnostics', action='store_true')
    parser.add_argument('--serve', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve:
        serve(args.serve, args.trace)
    else:
        benchmark(args)
