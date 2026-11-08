"""Native imported membership, direct refresh and packet lookup in an isolated namespace."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_native_sources_refresh_preserves_rule_handles_and_skips_unchanged_file():
    assert Path('/.dockerenv').exists()
    script = r'''
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
from types import SimpleNamespace

from nvyr.config_scripts import firewall
from nvyr.helpers import firewall_lists as feeds, nftables
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree
from tests.lifecycle import RuntimeEngine, firewall_context
from tests.test_firewall_lists import config

directory = Path(tempfile.mkdtemp())
source = directory/'feed.csv'
source.write_text('127.0.0.1,127.0.0.1,59111,udp,drop\ninvalid,127.0.0.1,59111,udp,accept\n')
configuration = config(str(source), kind='map')
configuration['firewall']['ipv4'] = {'input': {'filter': {'rule': {'1': {'map': 'G'}}}}}
schema = Schema.bundled()
effective = ReadOnlyTree(schema.defaults(configuration))
previous = ReadOnlyTree(schema.defaults({}))
context = firewall_context(effective, previous, 'firewall', ('firewall',), previous_effective=previous, schema=schema)
context = replace(context, state_directory=directory)
feeds.manager = feeds.Manager(directory/'lists')
firewall.verify(effective, context)
plan = firewall.generate(effective, context)
nftables.manager.apply(plan['rules'], directory)
feeds.manager.publish(plan['list-cache'])
subprocess.run(['ip','link','set','lo','up'],check=True)
engine = RuntimeEngine(running=configuration, schema=schema, mutex=threading.RLock(), busy=False,
                         unhealthy=False, store=SimpleNamespace(directory=directory))
def listed():
    return subprocess.check_output(['nft','-a','list','table','inet','nvyr_filter'],text=True)
handle = next(line for line in listed().splitlines() if 'comment "1|' in line)
receiver=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
receiver.bind(('127.0.0.1',59111))
receiver.settimeout(.2)
sender=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sender.sendto(b'drop',('127.0.0.1',59111))
try:
    receiver.recv(100)
    raise AssertionError('imported map did not drop')
except socket.timeout:
    pass
text=feeds.manager.update(engine, 'map', 'ipv4', 'G')['text']
assert 'replaced membership in 0' in text, text
(directory/'confirmed.json').write_text(json.dumps({'before': configuration, 'owner': 'test', 'deadline': 100}))
feeds.manager.checkpoint(directory)
source.write_text('127.0.0.1,127.0.0.1,59111,udp,accept\n')
text=feeds.manager.update(engine, 'map', 'ipv4', 'G')['text']
assert 'replaced membership in 1' in text, text
assert handle in listed()
sender.sendto(b'accept',('127.0.0.1',59111))
assert receiver.recv(100)==b'accept'
assert 'comment "A"' in listed()
feeds.fetch = lambda source: (_ for _ in ()).throw(AssertionError('rollback fetched a source'))
rollback = firewall.generate(effective, replace(context, recovery=True))
nftables.manager.apply(rollback['rules'], directory)
feeds.manager.publish(rollback['list-cache'])
sender.sendto(b'rollback',('127.0.0.1',59111))
try:
    receiver.recv(100)
    raise AssertionError('confirmed rollback did not restore imported drop')
except socket.timeout:
    pass
print('packet drop/accept/rollback, unchanged refresh, comment and stable rule handle passed')
'''
    result = subprocess.run(['unshare', '-n', sys.executable, '-c', script], text=True,
                            capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr


def test_native_automerge_comment_limitation_and_dynamic_refresh():
    script = r'''
import subprocess
def run(text):
    subprocess.run(['nft','-f','-'],input=text,text=True,check=True)
run(''' + "'''" + r'''
table inet imports {
 set ranges { type ipv4_addr; flags interval; auto-merge;
              elements = {192.0.2.0/25 comment "A", 192.0.2.128/25 comment "B"}; }
 set learned { type ipv4_addr; flags dynamic,timeout; timeout 10m; size 1024;
               elements = {192.0.2.1 comment "FEED", 192.0.2.2}; }
}
''' + "'''" + r''')
text=subprocess.check_output(['nft','list','table','inet','imports'],text=True)
assert '192.0.2.0/24 comment "A"' in text
run('flush set inet imports learned\nadd element inet imports learned { 192.0.2.3 comment "FEED" }\n')
text=subprocess.check_output(['nft','list','set','inet','imports','learned'],text=True)
assert '192.0.2.3' in text and '192.0.2.2' not in text and '192.0.2.1' not in text
'''
    result = subprocess.run(['unshare', '-n', sys.executable, '-c', script], text=True,
                            capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_http_transfer_deadline():
    """A connected source that never produces a body must not stall a commit."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    import time

    from nvyr.helpers.firewall_lists import fetch

    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', '100')
            self.end_headers()
            release.wait(10)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        with pytest.raises(ValueError, match='curl retrieval failed'):
            fetch(f'http://127.0.0.1:{server.server_port}/slow')
        assert 4 <= time.monotonic() - started < 7
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join()


def test_native_all_import_kinds_and_map_result_types():
    script = r'''
from dataclasses import replace
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace

from nvyr.config_scripts import firewall
from nvyr.helpers import firewall_lists as feeds, nftables
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree
from tests.lifecycle import RuntimeEngine, firewall_context

directory = Path(tempfile.mkdtemp())
root = {}
def source(name, text):
    path = directory / name
    path.write_text(text)
    return str(path)

for kind, family, text in (
    ('address-group', 'ipv4', '192.0.2.0/25\n192.0.2.128/25\n'),
    ('address-group', 'ipv6', '2001:db8::/65\n2001:db8:0:0:8000::/65\n'),
    ('interface-group', '', 'eth*\neth0\n'),
    ('mac-group', '', '02:00:00:00:00:01\n02:00:00:00:00:02\n'),
    ('port-group', '', '80-90\n85-95\n'),
):
    definitions = root.setdefault(kind, {})
    if family:
        definitions = definitions.setdefault(family, {})
    definitions['FEED'] = {'from-list': {'SOURCE': {'source': source(kind + family, text)}}}

root['address-group']['ipv4']['LEARNED'] = {'dynamic': {'timeout': '1s', 'size': '1024'},
    'from-list': {'SOURCE': {'source': source('learned', '192.0.2.200\n192.0.2.0/24\n')}}}

for family in ('ipv4', 'ipv6', 'inet'):
    definition = {'match': {'protocol': True}, 'from-csv': {'SOURCE': {
        'source': source('match' + family, 'udp\ntcp\n'), 'column': {'protocol': '1'}}}}
    root.setdefault('match-group', {}).setdefault(family, {})['FEED'] = definition
    for result_type in ('verdict',) if family == 'inet' else ('verdict', 'address', 'port', 'address-port'):
        result_columns = {'verdict': {'action': '2'}, 'address': {'address': '2'},
                          'port': {'port': '2'}, 'address-port': {'address': '2', 'port': '3'}}[result_type]
        address = '203.0.113.1' if family == 'ipv4' else '2001:db8::1'
        result = {'verdict': 'drop', 'address': address, 'port': '443', 'address-port': address + ',443'}[result_type]
        definition = {'match': {'protocol': True}, 'result-type': result_type, 'from-csv': {'SOURCE': {
            'source': source('map' + family + result_type, 'udp,' + result + '\n'),
            'column': {'protocol': '1', 'result': result_columns}}}}
        root.setdefault('map', {}).setdefault(family, {})[result_type.upper().replace('-', '_')] = definition

root['map']['ipv4']['OVERLAP'] = {'match': {'source-address': True}, 'result-type': 'verdict',
    'from-csv': {'SOURCE': {'source': source('overlap', '192.0.2.0/24,drop\n192.0.2.1,accept\n198.51.100.1,drop\n'),
                          'column': {'source-address': '1', 'result': {'action': '2'}}}}}
schema = Schema.bundled()
effective = ReadOnlyTree(schema.defaults({'firewall': {'group': root}}))
previous = ReadOnlyTree(schema.defaults({}))
context = firewall_context(effective, previous, 'firewall', ('firewall',), previous_effective=previous, schema=schema)
context = replace(context, state_directory=directory)
feeds.manager = feeds.Manager(directory/'cache')
firewall.verify(effective, context)
plan = firewall.generate(effective, context)
nftables.manager.apply(plan['rules'], directory)
feeds.manager.publish(plan['list-cache'])
listed = subprocess.check_output(['nft', 'list', 'map', 'inet', 'nvyr_filter', 'ipv4_map_OVERLAP'], text=True)
assert '198.51.100.1' in listed and '192.0.2.' not in listed, listed
listed = subprocess.check_output(['nft', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_LEARNED'], text=True)
assert '192.0.2.200' in listed and 'expires' in listed, listed
time.sleep(1.2)
engine = RuntimeEngine(running={'firewall': {'group': root}}, schema=schema,
                         mutex=threading.RLock(), busy=False, unhealthy=False,
                         store=SimpleNamespace(directory=directory))
result = feeds.manager.update(engine, 'address-group', 'ipv4', 'LEARNED')
assert 'replaced membership in 0' in result['text'], result
listed = subprocess.check_output(['nft', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_LEARNED'], text=True)
assert '192.0.2.200' not in listed, listed
'''
    result = subprocess.run(['unshare', '-n', sys.executable, '-c', script], text=True,
                            capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
