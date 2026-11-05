"""Unbound service files, live input snapshots, and serialized refresh operations.

The configuration script owns desired configuration. The periodic refresh only
re-renders that published intent when leases or interface addresses change.
"""

from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import shutil
import sys
import tempfile
import time

from nvyr.errors import RouterError
from nvyr.helpers import dhcp_hosts, interfaces, kea
from nvyr.helpers.process import cmd, run
from nvyr.helpers.template import render, write
from nvyr.storage import atomic_json

ROOT = Path('/run/nvyr-dns')
STATE = Path('/config/dns')


def instance_id(vrf):
    return vrf.encode().hex()


def control(vrf, *arguments):
    path = ROOT / instance_id(vrf) / 'unbound.conf'
    if not path.exists():
        raise RouterError(f'DNS forwarding is not configured in VRF {vrf}')
    return cmd(['unbound-control', '-c', str(path), *arguments], timeout=15)


def listener_addresses(section, vrf, devices):
    result = list(section.get('listen-address', ()))
    for interface in section.get('listen-interface', ()):
        device = devices.get(interface, {})
        if device.get('vrf') == vrf:
            for address in device.get('addresses', ()):
                if address in device.get('tentative', ()) or address in device.get('dadfailed', ()):
                    continue
                value = ipaddress.ip_address(address)
                # Link-local addresses need the interface scope when binding a socket.
                if value.version == 6 and value.is_link_local and not value.scope_id:
                    address = f'{address}%{interface}'
                result.append(address)
    if not section.get('listen-address') and not section.get('listen-interface'):
        result.extend(('127.0.0.1', '::1'))
    return sorted(set(result))


def is_listener(address, listeners, local):
    value = ipaddress.ip_address(address)
    for listener in listeners:
        bound = ipaddress.ip_address(listener)
        if value.version != bound.version:
            continue
        if value.packed == bound.packed:
            scopes = (getattr(value, 'scope_id', None), getattr(bound, 'scope_id', None))
            if not all(scopes) or scopes[0] == scopes[1]:
                return True
        if bound.is_unspecified and any(value.packed == assigned.packed for assigned in local):
            return True
    return False


def local_records(section, static, vrf):
    """Build A/AAAA and PTR records from managed data, never arbitrary hosts text."""
    options = section.get('local-data', {})
    records = []
    if 'static-host-mapping' in options:
        for name, mapping in sorted(static.items()):
            for address in mapping['address']:
                records.append((address, [name, *mapping.get('alias', ())]))
    if 'dhcp-leases' in options:
        for family in (4, 6):
            path = kea.RUNTIME / (kea.instance_name(family, vrf) + '.json')
            if not path.exists():
                continue
            configuration = json.loads(path.read_text())
            records.extend(dhcp_hosts.records(configuration, require_enabled=False))

    ttl = int(options.get('ttl', 300))
    result = set()
    for address, names in records:
        address = ipaddress.ip_address(address)
        valid = [dhcp_hosts.hostname(name) for name in names]
        valid = [name for name in valid if name]
        for name in valid:
            result.add(f'{name}. {ttl} IN {"A" if address.version == 4 else "AAAA"} {address}')
        if valid and 'disable-reverse' not in options:
            result.add(f'{address.reverse_pointer}. {ttl} IN PTR {valid[0]}.')
    return sorted(result)


def generate(intent, *, devices=None, offline=False):
    """Snapshot dynamic inputs and render native text without modifying the host."""
    if devices is None:
        devices = {} if offline or not intent['instances'] else kea.inventory()
    sources = set()
    for section in intent['instances'].values():
        for forwarding in [section, *section.get('domain', {}).values()]:
            sources.update(forwarding.get('name-server-interface', ()))
    learned = {} if offline or not sources else interfaces.manager.request('dns-sources', sources=sorted(sources))
    bundles = {}
    for vrf, section in intent['instances'].items():
        listeners = listener_addresses(section, vrf, devices)
        local = {ipaddress.ip_address(address) for device in devices.values() if device['vrf'] == vrf
                 for address in device['addresses']}
        zones = {}
        excluded = []
        for domain, forwarding in [('.', section), *section.get('domain', {}).items()]:
            endpoints = []
            for interface in forwarding.get('name-server-interface', ()):
                # Runtime changes can precede configd's next commit; never cross VRFs.
                if devices.get(interface, {}).get('vrf') != vrf:
                    continue
                for record in learned.get(interface, ()):
                    address = record.get('server')
                    if not address:
                        continue
                    if int(section.get('port', 53)) == 53 and is_listener(address, listeners, local):
                        excluded.append(address)
                    else:
                        endpoints.append(address)
            zones[domain] = sorted(set(endpoints))
        records = [] if offline else local_records(section, intent['static'], vrf)
        directory = ROOT / instance_id(vrf)
        variables = {'configuration': section, 'listeners': listeners, 'learned': zones, 'records': records,
                     'directory': str(directory), 'state': str(STATE / instance_id(vrf)), 'identifier': instance_id(vrf)}
        bundles[vrf] = {'text': render('dns/unbound.conf.j2', variables), 'listeners': listeners,
                        'configuration': section,
                        'learned': zones, 'records': records, 'excluded-upstreams': sorted(set(excluded)),
                        'waiting': not listeners, 'dnssec': 'disable' not in section.get('dnssec', {})}
    return bundles


@contextmanager
def locked():
    ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    ROOT.chmod(0o755)
    with (ROOT / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def initialize_state(vrf):
    account = pwd.getpwnam('unbound')
    STATE.mkdir(parents=True, exist_ok=True, mode=0o755)
    STATE.chmod(0o755)
    directory = STATE / instance_id(vrf)
    directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    directory.chmod(0o750)
    os.chown(directory, account.pw_uid, account.pw_gid)
    key = directory / 'root.key'
    if not key.exists():
        write(key, Path('/usr/share/dns/root.key').read_text(), mode=0o600)
    # Retained files can carry a previous image's numeric service account IDs.
    os.chown(key, account.pw_uid, account.pw_gid)


def active(vrf):
    return run(['systemctl', 'is-active', '--quiet', f'nvyr-dns@{instance_id(vrf)}.service']) == 0


def install_bundles(bundles):
    # Validate every instance before replacing any running configuration.
    for vrf, bundle in bundles.items():
        current = ROOT / instance_id(vrf) / 'unbound.conf'
        if current.exists() and current.read_text() == bundle['text']:
            continue
        current.parent.mkdir(mode=0o755, exist_ok=True)
        current.parent.chmod(0o755)
        initialize_state(vrf)
        with tempfile.NamedTemporaryFile(mode='w', dir=ROOT, suffix='.conf') as candidate:
            candidate.write(bundle['text'])
            candidate.flush()
            cmd(['unbound-checkconf', candidate.name], timeout=10)

    for directory in ROOT.iterdir():
        if directory.is_dir() and directory.name not in {instance_id(vrf) for vrf in bundles}:
            cmd(['systemctl', 'stop', f'nvyr-dns@{directory.name}.service'], timeout=20)
            shutil.rmtree(directory)

    for vrf, bundle in bundles.items():
        directory = ROOT / instance_id(vrf)
        directory.mkdir(mode=0o755, exist_ok=True)
        directory.chmod(0o755)
        sockets = directory / 'socket'
        sockets.mkdir(mode=0o700, exist_ok=True)
        account = pwd.getpwnam('unbound')
        os.chown(sockets, account.pw_uid, account.pw_gid)
        path = directory / 'unbound.conf'
        previous = path.read_text() if path.exists() else None
        observation = directory / 'status.json'
        old = json.loads(observation.read_text()) if observation.exists() else {}
        unit = f'nvyr-dns@{instance_id(vrf)}.service'
        if previous != bundle['text']:
            write(path, bundle['text'], mode=0o644)
        if bundle['waiting']:
            cmd(['systemctl', 'stop', unit], timeout=20)
        else:
            if (not active(vrf) or old.get('listeners') != bundle['listeners']
                    or old.get('configuration') != bundle['configuration']):
                cmd(['systemctl', 'restart', unit], timeout=20)
                deadline = time.monotonic() + 10
                while True:
                    try:
                        control(vrf, 'status')
                        break
                    except RouterError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
            elif previous != bundle['text']:
                control(vrf, 'reload_keep_cache')
            control(vrf, 'status')
        desired = {key: value for key, value in bundle.items() if key != 'text'}
        if old != desired:
            atomic_json(observation, desired)


def install(plan):
    with locked():
        install_bundles(plan['bundles'])
        atomic_json(ROOT / 'intent.json', plan['intent'])
        cmd(['systemctl', 'start' if plan['intent']['instances'] else 'stop', 'nvyr-dns-refresh.timer'], timeout=10)


def refresh():
    with locked():
        path = ROOT / 'intent.json'
        if path.exists():
            intent = json.loads(path.read_text())
            install_bundles(generate(intent))


def main():
    if len(sys.argv) == 2 and sys.argv[1] == 'refresh':
        refresh()
        return
    if len(sys.argv) != 2:
        raise SystemExit('Expected a DNS instance identifier or refresh')
    identifier = sys.argv[1]
    vrf = bytes.fromhex(identifier).decode()
    if instance_id(vrf) != identifier:
        raise SystemExit('Invalid DNS instance identifier')
    command = ['/usr/sbin/unbound', '-d', '-c', str(ROOT / identifier / 'unbound.conf')]
    if vrf != 'default':
        command = ['/usr/sbin/ip', 'vrf', 'exec', vrf, *command]
    os.execv(command[0], command)
