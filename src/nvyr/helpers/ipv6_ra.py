"""Publish delegated LAN prefixes and consume DNS options accepted by the Linux RA handler."""

import ipaddress
from pathlib import Path
import socket
import struct
import time

from nvyr.helpers import template
from nvyr.helpers.process import cmd
from nvyr.helpers.validators import dhcp_domain
from nvyr.helpers.dhcp6 import read
from nvyr.storage import atomic_json

ROOT = Path('/run/nvyr-netlink/pd-ra')


def advertise(name, allocations):
    state = ROOT / (name + '.json')
    config = state.with_suffix('.conf')
    previous = read(state)
    prefixes = {item['prefix']: [item['preferred'], item['valid']] for item in allocations}
    if not prefixes and not previous and not config.exists():
        return
    unit = f'nvyr-pd-ra@{name}.service'
    if not prefixes:
        cmd(['systemctl', 'stop', unit])
        state.unlink(missing_ok=True)
        config.unlink(missing_ok=True)
    elif prefixes != previous or not config.exists():
        now = time.monotonic()
        rows = [{'prefix': prefix, 'preferred': max(0, int(pref - now)), 'valid': max(0, int(valid - now))}
                for prefix, (pref, valid) in prefixes.items()]
        # Include an explicit withdrawal when another prefix still uses this RA service.
        rows.extend({'prefix': prefix, 'preferred': 0, 'valid': 0} for prefix in previous.keys() - prefixes.keys())
        ROOT.mkdir(parents=True, exist_ok=True)
        template.write(config, template.render('system/pd-ra.conf.j2', {'interface': name, 'prefixes': rows}))
        cmd(['systemctl', 'reload-or-restart', unit])
        atomic_json(state, prefixes)


def nd_options(payload):
    """Decode RTM_NEWNDUSEROPT, including the advertising router's source attribute."""
    if len(payload) < 24:
        return
    family, _, size, index, kind, code = struct.unpack_from('=BBHiBB', payload)
    if family != socket.AF_INET6 or kind != 134 or code or not 8 <= size <= len(payload) - 16:
        return
    data = payload[16:16 + size]
    attrs = payload[16 + ((size + 3) & ~3):]
    router = None
    while len(attrs) >= 4:
        length, attr = struct.unpack_from('=HH', attrs)
        if length < 4 or length > len(attrs):
            return
        if attr == 1 and length == 20:
            router = str(ipaddress.IPv6Address(attrs[4:20]))
        attrs = attrs[(length + 3) & ~3:]
    if not router or data[1] * 8 != len(data):
        return
    lifetime = int.from_bytes(data[4:8], 'big')
    if data[0] == 25 and (len(data) - 8) % 16 == 0:
        for pos in range(8, len(data), 16):
            yield index, router, 'server', str(ipaddress.IPv6Address(data[pos:pos + 16])), lifetime
    elif data[0] == 31:
        pos, labels = 8, []
        while pos < len(data):
            length = data[pos]
            pos += 1
            if not length:
                domain = '.'.join(labels)
                if labels and dhcp_domain(domain):
                    yield index, router, 'domain', domain, lifetime
                labels = []
                continue
            if length > 63 or pos + length > len(data) or not data[pos:pos + length].isascii():
                return
            labels.append(data[pos:pos + length].decode('ascii'))
            pos += length


class Learned:
    def __init__(self, path):
        self.path = Path(path)
        self.entries = read(self.path)

    def receive(self, packet):
        changed = False
        now = time.monotonic()
        while len(packet) >= 16:
            length, kind = struct.unpack_from('=IH', packet)
            if length < 16 or length > len(packet):
                break
            if kind == 68:  # RTM_NEWNDUSEROPT
                for index, router, record, value, lifetime in nd_options(packet[16:length]):
                    key = f'{index} {router} {record} {value}'
                    if lifetime:
                        self.entries[key] = now + lifetime
                    else:
                        self.entries.pop(key, None)
                    changed = True
            packet = packet[(length + 3) & ~3:]
        if changed:
            self.entries = {k: v for k, v in self.entries.items() if v > now}
            atomic_json(self.path, self.entries)
        return changed

    def expire(self, now):
        kept = {key: expiry for key, expiry in self.entries.items() if expiry > now}
        if kept == self.entries:
            return False
        self.entries = kept
        atomic_json(self.path, kept)
        return True

    def forget(self, index):
        kept = {key: expiry for key, expiry in self.entries.items() if not key.startswith(f'{index} ')}
        if kept != self.entries:
            self.entries = kept
            atomic_json(self.path, kept)

    def records(self, index, name):
        now = time.monotonic()
        for key, expiry in self.entries.items():
            link, _, kind, value = key.split()
            if link != str(index) or expiry <= now:
                continue
            if kind == 'server' and ipaddress.IPv6Address(value).is_link_local:
                value += '%' + name
            yield {kind: value, 'source': 'RA', 'interface': name}
