"""DHCPv6 negotiation and lease decoding. netlinkd owns interface configuration."""

import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import sys
import time
import uuid

from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import template
from nvyr.helpers.process import cmd
from nvyr.helpers.validators import dhcp_domain, dhcp_identifier
from nvyr.storage import atomic_json

ROOT = Path('/run/nvyr-netlink/dhcp6')
IDENTITIES = Path('/config/dhcpv6')
LEASE_DIR = Path('/var/lib/dhcpcd')
FLAGS = {'no-release', 'no-request-dns', 'no-request-domain-search', 'parameters-only', 'rapid-commit'}


def configuration(profile):
    requests = {}
    for key, pd in profile.get('dhcpv6-pd', {}).items():
        lans = {name: dict(values) for name, values in pd.get('interface', {}).items()}
        requests[key] = {'interface': lans}
        if 'length' in pd:
            requests[key]['length'] = pd['length']
    options = dict(profile.get('dhcpv6-options', {}))
    address = 'dhcpv6' in profile.get('address', ())
    return {'address': address, 'requests': requests, 'options': options} if address or requests or options else {}


def verify(name, spec, ipv6):
    from nvyr.helpers.netlink import interface_name

    options = spec['options']
    # A stateless Information-request cannot carry address or prefix associations.
    if 'parameters-only' in options and (spec['address'] or spec['requests']):
        raise ValidationError(f'{name}: parameters-only conflicts with address dhcpv6 and dhcpv6-pd')
    # Wire values must be safe to interpolate into the native client configuration.
    if set(options) - FLAGS - {'duid'} or ('duid' in options and not dhcp_identifier(options['duid'], 3, 130)):
        raise ValidationError(f'{name}: invalid DHCPv6 client options')
    # A DHCPv6 client needs a usable link-local source to reach the server.
    if 'disable' in ipv6 or 'no-default-link-local' in ipv6 and 'link-local-address' not in ipv6:
        raise ValidationError(f'{name}: DHCPv6 requires IPv6 and a link-local address')
    # A wire option needs a configured negotiation mode.
    if not (spec['address'] or spec['requests'] or 'parameters-only' in options):
        raise ValidationError(f'{name}: DHCPv6 options require an address, prefix request, or parameters-only')
    for key, pd in spec['requests'].items():
        # The native client parses numeric tokens with base autodetection.
        if not 0 <= int(key) <= 0xffffffff or str(int(key)) != key:
            raise ValidationError(f'{name}: invalid delegation ID {key}')
        length = int(pd.get('length', 1))
        # LAN assignments use /64 prefixes.
        if not 1 <= length <= 64:
            raise ValidationError(f'{name}: invalid prefix length {length}')
        used = set()
        for lan, values in pd['interface'].items():
            interface_name(lan)
            # A LAN needs its own /64, distinct from the uplink and other LANs.
            if lan == name or 'subnet-id' not in values:
                raise ValidationError(f'{name} PD {key}: select a downstream interface and specify its subnet-id')
            subnet = int(values['subnet-id'])
            if subnet in used or not 0 <= subnet < 1 << (64 - length):
                raise ValidationError(f'{name} PD {key}: duplicate or out-of-range subnet-id {subnet}')
            used.add(subnet)
            # The low 64 bits hold the router's unicast address.
            if not 1 <= int(values.get('address', 1)) < 1 << 64:
                raise ValidationError(f'{name} PD {key}: invalid router host number')


def native_config(name, spec, duid, token):
    options = spec['options']
    lines = ['noconfigure', 'noipv6rs', 'duid ' + duid, 'env NVYR_DHCP_TOKEN=' + token,
             'script /usr/bin/nvyr-dhcp6-hook', 'interface ' + name]
    if 'no-release' not in options:
        lines.append('release')
    for flag, native in [('no-request-dns', 'name_servers'), ('no-request-domain-search', 'domain_search')]:
        lines.append(('nooption' if flag in options else 'option') + ' dhcp6_' + native)
    if 'rapid-commit' in options:
        lines.append('option dhcp6_rapid_commit')
    if 'parameters-only' in options:
        lines.append('inform6')
    if spec['address']:
        lines.append('ia_na 0')
    if spec['requests']:
        lines.append('option dhcp6_pd_exclude')
    for key, pd in sorted(spec['requests'].items()):
        hint = '/::/' + str(int(pd['length'])) if 'length' in pd else ''
        lines.append(f'ia_pd {key}{hint} -')
    return '\n'.join(lines) + '\n'


def options(data):
    while data:
        code, length = struct.unpack_from('!HH', data)
        if length > len(data) - 4:
            raise ValueError('Truncated DHCPv6 option')
        yield code, data[4:4 + length]
        data = data[4 + length:]


def decode_reply(data, now):
    """Read IAIDs from the actual Reply. dhcpcd hook names merge repeated IA_PD options."""
    if not data or data[0] != 7:
        raise ValueError('Expected a DHCPv6 Reply')
    entries = []
    for code, ia in options(data[4:]):
        if code not in (3, 25):
            continue
        iaid, t1, t2 = struct.unpack_from('!III', ia)
        for kind, value in options(ia[12:]):
            if (code, kind) == (3, 5):
                address, preferred, valid = struct.unpack_from('!16sII', value)
                prefix = str(ipaddress.IPv6Address(address)) + '/128'
            elif (code, kind) == (25, 26):
                preferred, valid, length, address = struct.unpack_from('!IIB16s', value)
                prefix = str(ipaddress.IPv6Network((address, length)))
            else:
                continue
            entry = {'type': 'IA_NA' if code == 3 else 'IA_PD', 'id': str(iaid), 'prefix': prefix,
                     'preferred': now + preferred, 'valid': now + valid, 't1': t1, 't2': t2}
            if kind == 26:
                for option, exclusion in options(value[25:]):
                    if option == 67:
                        bits = exclusion[0] - length
                        if bits <= 0 or exclusion[0] > 128 or len(exclusion) != 1 + (bits + 7) // 8:
                            raise ValueError('Invalid DHCPv6 Prefix Exclude')
                        extra = int.from_bytes(exclusion[1:], 'big') >> (-bits % 8)
                        base = int(ipaddress.IPv6Address(address)) | extra << (128 - exclusion[0])
                        entry['excluded'] = str(ipaddress.IPv6Network((base, exclusion[0])))
            entries.append(entry)
    return entries


def assignments(spec, entries):
    result, unavailable = [], []
    for entry in entries:
        if entry['type'] != 'IA_PD':
            continue
        prefix = ipaddress.IPv6Network(entry['prefix'])
        pd = spec['requests'].get(entry['id'], {})
        for lan, setting in pd.get('interface', {}).items():
            subnet = int(setting['subnet-id'])
            if prefix.prefixlen > 64 or subnet >= 1 << (64 - prefix.prefixlen):
                unavailable.append(f"{lan}: subnet-id {subnet} does not fit {prefix}")
                continue
            base = int(prefix.network_address) | subnet << 64
            network = ipaddress.IPv6Network((base, 64))
            if 'excluded' in entry and network.overlaps(ipaddress.IPv6Network(entry['excluded'])):
                unavailable.append(f"{lan}: {network} overlaps the ISP's excluded prefix")
                continue
            address = ipaddress.IPv6Address(base + int(setting.get('address', 1)))
            result.append(dict(entry, interface=lan, address=f'{address}/64', prefix=str(network)))
    return result, unavailable


def read(path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {}


def hook_main():
    env = os.environ
    name, token, event = env['interface'], env['NVYR_DHCP_TOKEN'], env['reason']
    directory = ROOT / name
    if read(directory / 'client.json').get('token') != token:
        return
    path = directory / (token + '.json')
    if event in {'EXPIRE6', 'RELEASE6', 'STOP6', 'NOCARRIER', 'DEPARTED'}:
        path.unlink(missing_ok=True)
    elif event in {'BOUND6', 'RENEW6', 'REBIND6', 'REBOOT6', 'INFORM6'}:
        now = time.monotonic()
        lease = LEASE_DIR / (name + '.lease6')
        reply = lease.read_bytes()
        entries = decode_reply(reply, now)
        if event in ('RENEW6', 'REBIND6'):
            # Servers can omit an existing binding at renewal. Honor its original
            # valid lifetime. Prefer the replacement when the association renumbers.
            seen = {(e['type'], e['id'], e['prefix']) for e in entries}
            renewed = {(e['type'], e['id']) for e in entries if e['valid'] > now}
            for old in read(path).get('entries', ()):
                association = old['type'], old['id']
                if old['valid'] > now and (*association, old['prefix']) not in seen:
                    if association in renewed:
                        old['preferred'] = min(now, old['preferred'])
                    entries.append(old)
        metadata = {}
        if event == 'INFORM6':
            # A stateless Reply carries an Information Refresh Time in place of IA lifetimes.
            refresh = next((int.from_bytes(v, 'big') for code, v in options(reply[4:])
                            if code == 32 and len(v) == 4), 86400)
            metadata['refresh'] = now + max(600, refresh)
        atomic_json(path, {**metadata, 'entries': entries, 'dns': env.get('new_dhcp6_name_servers', '').split(),
                           'search': [s for s in env.get('new_dhcp6_domain_search', '').split() if dhcp_domain(s)],
                           'server': env.get('new_dhcp6_server_id'), 'received': now})


def client_main():
    name = sys.argv[1]
    path = ROOT / name
    state = read(path / 'client.json')
    if socket.if_nametoindex(name) != state['index']:
        raise RouterError(f'{name}: DHCPv6 client interface was replaced')
    # dhcpcd 10 tries changing Linux addrgenmode even with noconfigure.
    # Drop NET_ADMIN after VRF selection so kernel RA policy stays with netlinkd.
    argv = ['/usr/bin/setpriv', '--bounding-set=-net_admin', '/usr/sbin/dhcpcd', '-6', '-B', '-f', str(path / 'client.conf'), name]
    if state['vrf']:
        argv = ['/usr/sbin/ip', 'vrf', 'exec', state['vrf'], *argv]
    os.execv(argv[0], argv)


class Client:
    def __init__(self):
        self.checked = {}

    def stop(self, name):
        path = ROOT / name / 'client.json'
        state = read(path)
        if state:
            cmd(['systemctl', 'stop', f'nvyr-dhcp6@{name}.service'])
            path.unlink()
            path.with_name(state['token'] + '.json').unlink(missing_ok=True)
        self.checked.pop(name, None)

    def start(self, name, index, spec, vrf):
        directory = ROOT / name
        path = directory / 'client.json'
        state = read(path)
        desired = dict(index=index, spec=spec, vrf=vrf)
        # A LAN assignment changes local addressing only. Keep the ISP lease and its timers.
        if (state and state['index'] == index and state['vrf'] == vrf
                and spec.get('options') == state['spec'].get('options') and state['spec'] != spec
                and native_config(name, spec, state['duid'], state['token'])
                == native_config(name, state['spec'], state['duid'], state['token'])):
            state['spec'] = spec
            atomic_json(path, state)
        if any(state.get(k) != v for k, v in desired.items()):
            self.stop(name)
            identity = IDENTITIES / (name + '.json')
            duid = spec['options'].get('duid')
            if duid is None:
                duid = read(identity).get('duid')
                if not duid:
                    duid = (b'\x00\x04' + uuid.uuid4().bytes).hex(':')
                    atomic_json(identity, {'duid': duid})
            state = dict(desired, token=secrets.token_hex(16), duid=duid)
            directory.mkdir(parents=True, exist_ok=True)
            template.write(directory / 'client.conf', native_config(name, spec, duid, state['token']))
            atomic_json(path, state)
        if not state.get('released') and time.monotonic() >= self.checked.get(name, 0):
            cmd(['systemctl', 'start', f'nvyr-dhcp6@{name}.service'])
            self.checked[name] = time.monotonic() + 30

    def control(self, name, action):
        path = ROOT / name / 'client.json'
        state = read(path)
        if not state:
            raise RouterError(f'{name}: DHCPv6 client is unavailable')
        unit = f'nvyr-dhcp6@{name}.service'
        if action == 'release' and not state.get('released'):
            cmd(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGALRM', unit])
            atomic_json(path, dict(state, released=True))
            path.with_name(state['token'] + '.json').unlink(missing_ok=True)
        elif action == 'renew':
            if state.pop('released', False):
                cmd(['systemctl', 'restart', unit])
                atomic_json(path, state)
            else:
                cmd(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGUSR1', unit])

    def observation(self, name, index):
        directory = ROOT / name
        state = read(directory / 'client.json')
        if not state or state.get('index') != index:
            return {}
        if state.get('released'):
            return {'duid': state['duid']}
        lease = read(directory / (state['token'] + '.json'))
        now = time.monotonic()
        entries = [entry for entry in lease.get('entries', ()) if entry['valid'] > now]
        if (lease.get('entries') and not entries) or lease.get('refresh', float('inf')) <= now:
            lease = {}
        lans, errors = assignments(state['spec'], entries)
        return dict(lease, entries=entries, lans=lans, errors=errors, duid=state['duid'])
