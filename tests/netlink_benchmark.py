"""Opt-in real-kernel benchmark. Run ONLY in a fresh network namespace:

sudo unshare --net env PYTHONPATH=src python3 tests/netlink_benchmark.py 1000
Append --addresses to assign one IPv4 and one IPv6 address to every link.

No host interfaces, DHCP services or persistent nVyR state are touched.
"""

import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time

from nvyr.helpers.dhcp import DHCP
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from nvyr.netlink_daemon import Server


def main():
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise SystemExit('Run in a fresh isolated network namespace containing only lo')

    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    kernel = Kernel()

    with tempfile.TemporaryDirectory(prefix='nvyr-netlink-benchmark-') as directory:
        root = Path(directory)
        manager = Manager(kernel, DHCP(root/'runtime'), root/'state')
        links = {f'dum{i}': {'kind': 'dummy', 'attributes': {'mtu': 1500}} for i in range(count)}

        if '--addresses' in sys.argv:
            for i, definition in enumerate(links.values()):
                definition['addresses'] = [f'198.18.{i//256}.{i%256}/32', f'2001:db8::{i+1:x}/128']

        timings = {'interfaces': count, 'dual_stack': '--addresses' in sys.argv}

        def measure(label, action):
            start = time.monotonic()
            action()
            timings[label] = round(time.monotonic() - start, 4)
            print(json.dumps({label: timings[label]}), flush=True)

        measure('create_seconds', lambda: manager.replace('dummy', links))
        measure('unchanged_apply_seconds', lambda: manager.replace('dummy', links))
        measure('audit_seconds', manager.reconcile)
        calls = []
        original = manager.reconcile

        def reconcile(*args, **kwargs):
            calls.append(None if not args or args[0] is None else len(args[0]))
            return original(*args, **kwargs)

        manager.reconcile = reconcile
        server = Server(manager, root/'control.sock')
        ready = threading.Event()
        thread = threading.Thread(target=lambda: server.run(ready=ready.set))
        thread.start()

        try:
            assert ready.wait(5)

            time.sleep(3)  # Allow initial audit and queued DAD notifications.
            calls.clear()
            cpu, wall = time.process_time(), time.monotonic()
            time.sleep(5)
            timings['idle_cpu_percent'] = round(100 * (time.process_time()-cpu)/(time.monotonic()-wall), 3)
            timings['idle_reconciliations'] = list(calls)

            def wait_for(predicate):
                deadline = time.monotonic()+10

                while not predicate():
                    assert thread.is_alive() and time.monotonic() < deadline, manager.error

                    time.sleep(.02)

            # A separate socket simulates another administrator/kernel actor.
            external = Kernel()

            try:
                calls.clear()

                def drift():
                    external.ipr.link('set', index=external.device('dum0')['index'], mtu=9000, state='down')
                    wait_for(lambda: external.device('dum0')['up'] and external.device('dum0')['attributes']['mtu'] == 1500)

                measure('drift_repair_seconds', drift)
                timings['drift_reconciliations'] = list(calls)

                def deletion():
                    index = external.device('dum1')['index']
                    external.ipr.link('del', index=index)
                    wait_for(lambda: (external.device('dum1') or {}).get('index', index) != index)
                    wait_for(lambda: external.device('dum1')['up'])

                measure('delete_repair_seconds', deletion)

                def address():
                    external.ipr.addr('add', index=external.device('dum2')['index'], address='192.0.2.1', prefixlen=32)
                    wait_for(lambda: '192.0.2.1/32' not in external.addresses('dum2'))

                measure('address_repair_seconds', address)
            finally:
                external.close()
        finally:
            server.running = False
            thread.join(10)

            assert not thread.is_alive()

        measure('remove_seconds', lambda: manager.replace('dummy', {}))
        print(json.dumps(timings, sort_keys=True), flush=True)

    kernel.close()


if __name__ == '__main__':
    main()
