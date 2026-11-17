"""Native WireGuard synchronization and bounded endpoint resolution.

The small endpoint manifest records configured intent, not connection history.
It lets unrelated reconciliation preserve native roaming and serializes manual
or scheduled DNS updates with interface application.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import base64
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import time

import dns.exception
import dns.resolver

from nvyr.errors import OperationalError, Warning
from nvyr.helpers.process import cmd
from nvyr.helpers import template
from nvyr.storage import atomic_json

DIRECTORY = Path('/run/nvyr-netlink/wireguard')
ZERO_KEY = base64.b64encode(bytes(32)).decode()


def hostname(address):
    try:
        ipaddress.ip_address(address)
        return False
    except ValueError:
        return True


def endpoint_text(address, port):
    return f'[{address}]:{port}' if ':' in address else f'{address}:{port}'


def resolve(endpoint, current=None):
    """Use one three-second deadline for both DNS families, retaining a valid answer."""
    address, port = endpoint['address'], endpoint['port']
    if not hostname(address):
        return endpoint_text(str(ipaddress.ip_address(address)), port)
    family = endpoint.get('address-family', 'auto')
    try:
        resolver = dns.resolver.Resolver()
    except dns.exception.DNSException as error:
        raise OperationalError(f'WireGuard endpoint {address}: DNS resolver unavailable: {error}') from error
    resolver.timeout = 1
    deadline = time.monotonic() + 3
    answers = []
    for kind in (('A', 'AAAA') if family == 'auto' else ('A',) if family == 'ipv4' else ('AAAA',)):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            records = resolver.resolve(address, kind, lifetime=remaining, search=False)
            answers.extend(endpoint_text(str(record), port) for record in records)
        except dns.exception.DNSException:
            continue
    if not answers:
        raise OperationalError(f'WireGuard endpoint {address}: no usable DNS answer within three seconds')
    return current if current in answers else answers[0]


def manifest(name):
    from nvyr.helpers.netlink import interface_name

    path = DIRECTORY / (interface_name(name) + '.json')
    return json.loads(path.read_text()) if path.exists() else {}


@contextmanager
def locked(name):
    import fcntl
    from nvyr.helpers.netlink import interface_name

    DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (DIRECTORY / (interface_name(name) + '.lock')).open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def state(name, *, secrets=False):
    """Read native state once; include secret fields only for synchronization."""
    lines = cmd(['wg', 'show', name, 'dump']).splitlines()
    if not lines:
        raise OperationalError(f'WireGuard interface {name} is unavailable')
    interface = lines[0].split('\t')
    peers = {}
    for line in lines[1:]:
        fields = line.split('\t')
        peers[fields[0]] = {
            'endpoint': None if fields[2] == '(none)' else fields[2],
            'allowed-ips': [] if fields[3] == '(none)' else fields[3].split(','),
            'handshake': int(fields[4]), 'received': int(fields[5]), 'sent': int(fields[6]),
            'keepalive': 0 if fields[7] == 'off' else int(fields[7]),
            'preshared': fields[1] != '(none)',
        }
        if secrets:
            peers[fields[0]]['preshared-key'] = ZERO_KEY if fields[1] == '(none)' else fields[1]
    result = {'public-key': interface[1], 'listen-port': int(interface[2]),
              'firewall-mark': interface[3], 'peers': peers}
    if secrets:
        result['private-key'] = interface[0]
    return result


def endpoint_identity(endpoint):
    return {key: value for key, value in endpoint.items() if key != 'resolve-interval'}


def prepare_endpoints(name, peers, report):
    previous = manifest(name).get('peers', {})

    def prepare(item):
        peer_name, peer = item
        endpoint = peer['endpoint']
        old = previous.get(peer_name, {})
        resolved = old.get('resolved')
        if endpoint:
            if endpoint_identity(endpoint) != endpoint_identity(old.get('endpoint', {})) or not resolved:
                try:
                    resolved = resolve(endpoint, resolved)
                except OperationalError as error:
                    report(Warning(f'{name} peer {peer_name}: {error}; retaining an existing endpoint if available'))
        else:
            resolved = None
        return peer_name, dict(peer, resolved=resolved)

    with ThreadPoolExecutor(max_workers=8) as executor:
        return dict(executor.map(prepare, peers.items()))


def configuration_text(settings, peers):
    return template.render('wireguard/interface.conf.j2', {'settings': settings, 'peers': peers})


def private_identity(key):
    """Compare X25519 identities after the kernel's scalar clamping."""
    if key == '(none)':
        return None
    value = bytearray(base64.b64decode(key))
    value[0] &= 248
    value[31] = (value[31] & 127) | 64
    return bytes(value)


def native_matches(settings, peers, live):
    if private_identity(settings['private-key']) != private_identity(live['private-key']):
        return False
    mark = 0 if live['firewall-mark'] == 'off' else int(live['firewall-mark'], 16)
    if settings['listen-port'] != live['listen-port'] or settings['firewall-mark'] != mark:
        return False
    wanted = {peer['public-key']: peer for peer in peers.values()}
    if wanted.keys() != live['peers'].keys():
        return False
    for key, peer in wanted.items():
        current = live['peers'][key]
        if (peer['preshared-key'] != current['preshared-key'] or
                set(peer['allowed-ips']) != set(current['allowed-ips']) or
                peer['persistent-keepalive'] != current['keepalive'] or
                peer['resolved'] != current['endpoint']):
            return False
    return True


def synchronize(name, settings, disabled=False):
    with locked(name):
        before = manifest(name)
        previous = before.get('peers', {})
        live = state(name, secrets=True)
        peers, metadata = {}, {}
        for peer_name, peer in settings['peers'].items():
            old = previous.get(peer_name, {})
            current = live['peers'].get(peer['public-key'], {})
            same = (old.get('public-key') == peer['public-key'] and
                    endpoint_identity(old.get('endpoint', {})) == endpoint_identity(peer['endpoint']))
            endpoint = peer.get('resolved')
            if same or endpoint is None and peer['endpoint']:
                endpoint = current.get('endpoint') or endpoint
            if same and endpoint is None:
                endpoint = old.get('resolved')
            # Omitting Endpoint in syncconf preserves it. Recreate only a peer whose
            # configured endpoint was explicitly removed, to clear that native state.
            if not peer['endpoint'] and old.get('endpoint') and current.get('endpoint'):
                cmd(['wg', 'set', name, 'peer', peer['public-key'], 'remove'])
            elif not peer['endpoint']:
                endpoint = current.get('endpoint')
            peers[peer_name] = dict(peer, resolved=endpoint)
            metadata[peer_name] = {key: peer[key] for key in ('public-key', 'endpoint')}
            metadata[peer_name]['resolved'] = endpoint
        # Avoid resetting an automatically selected port on every netlink audit.
        port = settings['listen-port']
        if not port and not before.get('listen-port'):
            port = live['listen-port']
        effective = dict(settings, **{'listen-port': port})
        if not native_matches(effective, peers, live):
            descriptor, filename = tempfile.mkstemp(prefix='wg-', dir=DIRECTORY)
            try:
                with os.fdopen(descriptor, 'w') as stream:
                    stream.write(configuration_text(effective, peers))
                cmd(['wg', 'syncconf', name, filename])
            finally:
                Path(filename).unlink(missing_ok=True)
        document = {'disabled': disabled, 'listen-port': settings['listen-port'], 'peers': metadata}
        if manifest(name) != document:
            atomic_json(DIRECTORY / (name + '.json'), document)


def forget(name):
    with locked(name):
        (DIRECTORY / (name + '.json')).unlink(missing_ok=True)


def refresh(name, peer=None, scheduled=False, unresolved=False):
    with locked(name):
        document = manifest(name)
        if not document or document.get('disabled'):
            raise OperationalError(f'{name}: no enabled managed WireGuard interface')
        peers = document['peers']
        if peer is not None and peer not in peers:
            raise OperationalError(f'{name}: peer {peer} is not enabled')
        live = state(name)
        messages, failures = [], []
        for peer_name, settings in peers.items():
            if peer is not None and peer != peer_name:
                continue
            endpoint = settings['endpoint']
            if not endpoint or not hostname(endpoint['address']):
                continue
            current = live['peers'].get(settings['public-key'])
            if current is None:
                continue
            if unresolved and current['endpoint']:
                continue
            if scheduled and time.time() - current['handshake'] < 135:
                messages.append(f'{name} peer {peer_name}: recent handshake; retained current endpoint')
                continue
            # Resolution failures leave the native peer untouched and remain visible in task logs.
            try:
                resolved = resolve(endpoint, current['endpoint'])
            except OperationalError as error:
                failures.append(f'{name} peer {peer_name}: {error}')
                continue
            if resolved != current['endpoint']:
                cmd(['wg', 'set', name, 'peer', settings['public-key'], 'endpoint', resolved])
            settings['resolved'] = resolved
            messages.append(f'{name} peer {peer_name}: {resolved}')
        atomic_json(DIRECTORY / (name + '.json'), document)
        if failures:
            raise OperationalError('\n'.join(messages + failures))
        return '\n'.join(messages) or f'{name}: no hostname endpoints to refresh'
