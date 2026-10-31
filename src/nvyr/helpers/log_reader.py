"""Read and follow selected log files, retaining exact nftables prefix scopes."""

import os
from pathlib import Path
import re
import stat
import time

from nvyr.errors import OperationalError
from nvyr.helpers.logging_formatters import ROOT, SERVICES
from nvyr.helpers.nftables_formatters import NFT_FILTER_HOOKS, NFT_HOOK_LABELS, NFT_NAT_HOOK_LABELS


def identifier(value):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}', value):
        raise OperationalError('Invalid log identifier.')
    return value


def select(service, *, root=ROOT, name='', vrf='default', family='', hook='', stage='', rule='', chain='', group='', direction=''):
    """Resolve only fixed service paths; CLI values never become arbitrary paths."""
    root = Path(root)
    pattern = None
    if service == 'firewall':
        if group:
            paths = lambda: [root / 'firewall' / ('group-' + identifier(group) + '.log')]
        else:
            paths = lambda: sorted((root / 'firewall').glob('*.log'))
        if family:
            if family not in ('ipv4', 'ipv6', 'inet'):
                raise OperationalError('Expected IPv4, IPv6 or inet.')
            prefix = r'\[' + family + '-'
            if chain:
                prefix += re.escape('name_' + identifier(chain)) + '-'
            elif hook:
                if hook not in NFT_HOOK_LABELS or stage and (hook, stage) not in NFT_FILTER_HOOKS.values():
                    raise OperationalError('Unsupported firewall hook or priority.')
                prefix += NFT_HOOK_LABELS[hook] + '-'
                prefix += re.escape(stage) + '-' if stage else '(?:filter|raw)-'
            if rule:
                if not (chain or hook and stage) or not re.fullmatch(r'[1-9][0-9]{0,5}', rule):
                    raise OperationalError('Select a chain and a rule number from 1 to 999999.')
                prefix += rule + r'-[A-Z]\]'
            pattern = re.compile(prefix)
    elif service == 'nat':
        paths = lambda: sorted((root / 'firewall').glob('*.log'))
        if direction and direction not in NFT_NAT_HOOK_LABELS:
            raise OperationalError('Expected source or destination NAT.')
        label = NFT_NAT_HOOK_LABELS[direction] if direction else '(?:PRE|POST)'
        if rule and not re.fullmatch(r'[1-9][0-9]{0,5}', rule):
            raise OperationalError('Expected a rule number from 1 to 999999.')
        number = rule or '[0-9]+'
        pattern = re.compile(r'\[ipv4-' + label + '-' + number + r'-[A-Z]+\]')
    elif service == 'container':
        container = identifier(name)
        paths = lambda: [root / 'containers' / (container + '.log')]
    elif service in ('dhcp-server', 'dhcpv6-server'):
        paths = lambda: [root / service / (identifier(vrf).encode().hex() + '.log')]
    elif service in SERVICES or service in ('system', 'kernel', 'authentication'):
        paths = lambda: [root / (service + '.log')]
    else:
        raise OperationalError('Unknown log service.')
    return paths, pattern


def _open(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OperationalError(f'Not a regular log file: {path.name}')
        return os.fdopen(descriptor, encoding='utf-8', errors='replace')
    except BaseException:
        os.close(descriptor)
        raise


def records(paths, pattern=None, *, follow=False, sleep=time.sleep):
    """Drain old inodes before following replacements; never reread old records."""
    streams = {}
    pending = {}
    try:
        while True:
            for path in paths():
                stream = streams.get(path)
                if stream is None:
                    stream = _open(path)
                    if stream is None:
                        continue
                    streams[path] = stream
                # Stream large files without retaining the entire log in memory.
                text = pending.pop(path, '')
                while chunk := stream.readline(65536):
                    text += chunk
                    if text.endswith('\n'):
                        if pattern is None or pattern.search(text):
                            yield path, text
                        text = ''
                if text:
                    if follow:
                        pending[path] = text
                    elif pattern is None or pattern.search(text):
                        yield path, text

                if follow:
                    try:
                        current = path.stat()
                    except FileNotFoundError:
                        continue
                    old = os.fstat(stream.fileno())
                    if (old.st_dev, old.st_ino) != (current.st_dev, current.st_ino):
                        # A writer may finish a record during rename/reopen.
                        tail = pending.pop(path, '')
                        for chunk in stream:
                            tail += chunk
                            if pattern is None or pattern.search(tail):
                                yield path, tail
                            tail = ''
                        if tail and (pattern is None or pattern.search(tail)):
                            yield path, tail
                        stream.close()
                        del streams[path]
                    elif current.st_size < stream.tell():
                        stream.seek(0)
                        pending.pop(path, None)
            if not follow:
                break
            sleep(0.2)
    finally:
        for stream in streams.values():
            stream.close()


def container_line(line):
    """Keep timestamp and stream while removing Conmon's CRI framing marker."""
    fields = line.split(' ', 3)
    if len(fields) == 4 and fields[1] in ('stdout', 'stderr') and fields[2] in ('F', 'P'):
        return fields[0] + ' ' + fields[1] + ': ' + fields[3]
    return line
