"""Fetch external firewall membership and replace elements without rebuilding rules."""

from concurrent.futures import ThreadPoolExecutor
from collections.abc import Mapping
from contextlib import closing
from copy import deepcopy
import csv
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
from importlib.resources import files
import json
import logging
from logging.handlers import SysLogHandler
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import time

from nvyr.errors import BusyError, RecoveryError, RouterError, ValidationError, Warning
from nvyr.helpers import access, nftables, task_schedule
from nvyr.helpers import nftables_formatters as nft
from nvyr.schema import Schema
from nvyr.storage import atomic_json
from nvyr.tree import lookup


KINDS = ('address-group', 'interface-group', 'mac-group', 'port-group', 'match-group', 'map')
CONNECT_TIMEOUT = 2
FETCH_TIMEOUT = 5
WORKERS = 10
PROTOCOLS = 'http,https,ftp,ftps,tftp'
log = logging.getLogger('nvyr.firewall-lists')


def attachment_node(kind):
    return 'from-csv' if kind in ('match-group', 'map') else 'from-list'


def groups(configuration):
    result = {}
    root = lookup(configuration, ('firewall', 'group'), {})
    for kind in KINDS:
        if kind in ('map', 'match-group'):
            families = ('ipv4', 'ipv6', 'inet')
        elif kind == 'address-group':
            families = ('ipv4', 'ipv6')
        else:
            families = ('',)
        for family in families:
            definitions = lookup(root, (kind, family) if family else (kind,), {})
            for name, definition in definitions.items():
                if attachment_node(kind) in definition:
                    result[(kind, family, name)] = definition
    return result


def leaves(tree, prefix=()):
    for key, value in tree.items():
        path = (*prefix, key)
        if isinstance(value, Mapping):
            yield from leaves(value, path)
        else:
            yield path, value


def field_path(field):
    return nft.NFT_KEYMAP[field].path or (field,)


def verify(configuration):
    for (kind, family, name), definition in groups(configuration).items():
        path = ' '.join(filter(None, ('firewall group', kind, family, name)))
        manual = 'entry' if kind in ('map', 'match-group') else nft.NFT_SINGLETON_GROUPS[kind][0]
        # Sources own membership; manual/inherited membership cannot be refreshed independently.
        if any(key in definition for key in (manual, 'include-group', 'geoip')):
            raise ValidationError(f'{path}: imported membership cannot coexist with {manual}, include-group or geoip')
        fields = {field_path(field) for field in nft.nft_group_fields(definition)} if manual == 'entry' else set()
        for attachment, options in definition[attachment_node(kind)].items():
            location = f'{path} {attachment_node(kind)} {attachment}'
            # A configured attachment needs a source even if retrieval later fails.
            if 'source' not in options:
                raise ValidationError(f'{location}: source is required')
            # Interval and calendar have different timing semantics.
            if 'interval' in options and 'calendar' in options:
                raise ValidationError(f'{location}: interval and calendar are mutually exclusive')
            # A calendar without a time cannot produce a systemd schedule.
            if 'calendar' in options and not lookup(options, ('calendar', 'at'), ()):
                raise ValidationError(f'{location}: calendar requires at least one time')
            if manual != 'entry':
                continue
            columns = dict(leaves(lookup(options, ('column',), {})))
            keys = {key for key in columns if key[0] != 'result'}
            # Explicit column mappings must cover precisely the group's selected key fields.
            if keys != fields:
                raise ValidationError(f'{location}: column mappings must match the selected match fields')
            results = {key[1] for key in columns if key[0] == 'result'}
            required = {'verdict': {'action'}, 'address': {'address'}, 'port': {'port'},
                        'address-port': {'address', 'port'}}.get(lookup(definition, ('result-type',), None), set())
            # Verdict CSVs may supply jump targets; individual rows determine whether they are required.
            allowed = required | ({'jump-target'} if required == {'action'} else set())
            if not required <= results <= allowed:
                raise ValidationError(f'{location}: result columns do not match result-type')


@lru_cache(maxsize=1)
def schema():
    return Schema(json.loads(files('nvyr').joinpath('schemas/configuration.json').read_text()))


def entry_schema(identity):
    kind, family, name = identity
    path = ('firewall', 'group', kind, family) if family else ('firewall', 'group', kind)
    node = schema().root
    for part in path:
        node = node['children'][part]
    return node['children']['entry'] if kind in ('map', 'match-group') else node['children'][nft.NFT_SINGLETON_GROUPS[kind][0]]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    default=lambda item: dict(item) if isinstance(item, Mapping) else list(item)).encode()).hexdigest()


def report(message, output=None, *, warning=False):
    # A dedicated identifier routes through the existing rsyslog/rotation system.
    if not log.handlers and os.path.exists('/dev/log'):
        handler = SysLogHandler(address='/dev/log')
        handler.setFormatter(logging.Formatter('nvyr-firewall-lists: %(message)s'))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        log.propagate = False
    log.log(logging.WARNING if warning else logging.INFO, '%s', message)
    if output is not None:
        output(Warning(message) if warning else message + '\n')


def fetch(source):
    """Bound DNS/connect and total transfer time; never invoke a shell or log credentials."""
    if source.startswith('/'):
        descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('source is not a regular file')
            return stream.read()
    with tempfile.TemporaryDirectory(prefix='nvyr-feed-') as directory:
        destination = Path(directory) / 'download'
        # A subprocess deadline also bounds builds of curl using a blocking resolver.
        argv = ['curl', '--disable', '--silent', '--show-error', '--fail', '--location',
                '--globoff', '--proto', '=' + PROTOCOLS, '--proto-redir', '=http,https,ftp,ftps',
                '--connect-timeout', str(CONNECT_TIMEOUT), '--max-time', str(FETCH_TIMEOUT),
                '--output', str(destination), '--url', source]
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=FETCH_TIMEOUT + 1, check=False)
        except subprocess.TimeoutExpired:
            raise ValueError(f'retrieval exceeded {FETCH_TIMEOUT + 1} seconds') from None
        if result.returncode:
            raise ValueError(f'curl retrieval failed (exit {result.returncode})')
        return destination.read_bytes()


def put_entry(entry, path, value):
    for part in path[:-1]:
        entry = entry.setdefault(part, {})
    entry[path[-1]] = value


def parse(data, identity, definition, options, configuration, emit):
    from nvyr.config_scripts import firewall

    kind, family, name = identity
    columns = dict(leaves(options.get('column', {})))
    node = entry_schema(identity)
    fields = nft.nft_group_fields(definition) if columns else [nft.NFT_SINGLETON_GROUPS[kind][1]]
    named = lookup(configuration, ('firewall', family, 'name'), {})
    text = data.decode('utf-8-sig', errors='replace')
    entries = {}
    ambiguous = set()
    jump_checks = {}
    counts = {'accepted': 0, 'invalid': 0, 'duplicates': 0}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or (not columns and line.lstrip().startswith('#')):
            continue
        try:
            row = next(csv.reader([line], strict=True)) if columns else [line]
            entry = {}
            if columns:
                for path, column in columns.items():
                    value = row[int(column) - 1].strip()
                    if path == ('result', 'jump-target') and not value:
                        continue
                    field_node = node
                    for part in path:
                        field_node = field_node['children'][part]
                    schema().validate(field_node, value)
                    put_entry(entry, path, value)
                candidate = {key: value for key, value in definition.items() if key not in ('entry', 'from-csv')}
                candidate['entry'] = {'import': entry}
                if 'port' in entry.get('result', {}):
                    entry['result']['port'] = str(int(entry['result']['port']))
                # Dynamic declarations reject configured members, but imported exact keys are allowed.
                candidate.pop('dynamic', None)
                firewall._verify_group(family, name, candidate, kind, named)
                target = lookup(entry, ('result', 'jump-target'), None)
                if target:
                    # CSV jumps obey every calling hook; cache this check per target, not per row.
                    if target not in jump_checks:
                        maps = dict(lookup(configuration, ('firewall', 'group', 'map', family), {}))
                        maps[name] = candidate
                        try:
                            firewall._verify_hook_constraints(configuration, family, named, maps,
                                lookup(configuration, ('firewall', 'group', 'match-group', family), {}))
                            jump_checks[target] = None
                        except ValidationError as error:
                            jump_checks[target] = str(error)
                    if jump_checks[target]:
                        raise ValueError(jump_checks[target])
            else:
                value = row[0].strip()
                schema().validate(node, value)
                entry[fields[0]] = value
            # Learned sets use exact keys; intervals are not supported by their native backend.
            if 'dynamic' in definition and any('/' in nft.nft_field_value(entry, field) or
                    '-' in nft.nft_field_value(entry, field) for field in fields
                    if field.endswith(('-address', '-port')) or nft.NFT_KEYMAP[field].interval):
                raise ValueError('dynamic groups require exact keys, not prefixes or ranges')
            flags = nft.tcp_flag_values(entry['tcp-flags'], 255) if 'tcp-flags' in fields else [None]
            result = nft._nft_map_result(family, definition['result-type'], entry['result']) if kind == 'map' else None
            for flag in flags:
                canonical = tuple((flag, flag) if field == 'tcp-flags' else firewall._group_interval(
                    field, nft.nft_field_value(entry, field), family) for field in fields)
                key = json.dumps(canonical, separators=(',', ':'))
                native = ' . '.join(str(flag) if field == 'tcp-flags' else nft._nft_group_value(
                    field, nft.nft_field_value(entry, field)) for field in fields)
                value = {'key': native, 'result': result, 'row': number}
                if key in ambiguous:
                    continue
                if key in entries and entries[key]['result'] != result:
                    emit(f'row {number}: ambiguous key {native}; results {entries[key]["result"]!r} and {result!r}; excluding key')
                    del entries[key]
                    ambiguous.add(key)
                elif key in entries:
                    counts['duplicates'] += 1
                else:
                    entries[key] = value
            counts['accepted'] += 1
        except (ValidationError, ValueError, IndexError, KeyError, csv.Error) as error:
            counts['invalid'] += 1
            emit(f'row {number}: {error}')
    return {'entries': entries, 'ambiguous': sorted(ambiguous), 'counts': counts}


def object_id(identity):
    kind, family, name = identity
    if kind == 'map':
        return 'map', nft.nft_map_name(family, name)
    if kind == 'match-group':
        return 'set', nft.nft_match_group_name(family, name)
    return 'set', nft.nft_singleton_name(kind, family or None, name)


def remove_overlapping_map_keys(entries, emit):
    """Exclude entire overlap clusters in O(n log n), without choosing a winner."""
    intervals = sorted((*json.loads(key)[0], key) for key in entries)
    cluster = []
    end = None

    def discard():
        if len(cluster) > 1:
            for key in cluster:
                entry = entries.pop(key)
                emit(f'overlapping single-field map key {entry["key"]} '
                     f'from {", ".join(sorted(entry["origins"]))}; excluding key')

    for lower, upper, key in intervals:
        if cluster and lower > end:
            discard()
            cluster = []
        end = max(end, upper) if cluster else upper
        cluster.append(key)
    discard()


def elements(identity, definition, records, emit):
    merged = {}
    ambiguous = set()
    for attachment, record in sorted(records.items()):
        ambiguous.update(record.get('ambiguous', ()))
        for key, entry in record.get('entries', {}).items():
            if key in ambiguous:
                continue
            previous = merged.get(key)
            if previous is not None and previous['result'] != entry['result']:
                emit(f'ambiguous key {entry["key"]}: {sorted(previous["origins"])} and {attachment}; '
                     f'results {previous["result"]!r} and {entry["result"]!r}; excluding key')
                ambiguous.add(key)
                del merged[key]
            elif previous is not None:
                previous['origins'].add(attachment)
            else:
                merged[key] = entry | {'origins': {attachment}}
    for key in ambiguous:
        merged.pop(key, None)
    if identity[0] == 'map' and len(nft.nft_group_fields(definition)) == 1:
        remove_overlapping_map_keys(merged, emit)
    if 'dynamic' in definition:
        capacity = int(definition['dynamic']['size'])
        if len(merged) > capacity:
            emit(f'{identity}: {len(merged) - capacity} entries exceed the dynamic group size {capacity}; skipping excess entries')
            merged = dict(sorted(merged.items())[:capacity])
    values = []
    for key, entry in sorted(merged.items()):
        comment = ', '.join(sorted(entry['origins']))
        # Native comments have a 128-byte limit; source names are ASCII schema tokens.
        if len(comment) > 128:
            comment = comment[:125] + '...'
        text = entry['key'] + ' comment ' + json.dumps(comment)
        if entry['result'] is not None:
            text += ' : ' + entry['result']
        values.append(text)
    if identity[0] == 'map' and 'default-result' in definition:
        values.append('* : ' + nft._nft_map_result(identity[1], definition['result-type'], definition['default-result']))
    kind, name = object_id(identity)
    target = 'inet nvyr_filter ' + name
    lines = [f'flush {kind} {target}']
    if values:
        lines.append('add element ' + target + ' { ' + ', '.join(values) + ' }')
    return '\n'.join(lines) + '\n', len(merged)


def schedule_options(options):
    return {key: options[key] for key in ('interval', 'calendar') if key in options}


def schedule_name(options):
    return digest(schedule_options(options))[:32]


def schedules(selections):
    grouped = {}
    for identity, definition in selections.items():
        for attachment, options in definition[attachment_node(identity[0])].items():
            schedule = schedule_options(options)
            if schedule:
                grouped[schedule_name(options)] = schedule

    desired = {}
    for name, schedule in grouped.items():
        argv = ['/usr/bin/python3', '-m', 'nvyr.helpers.firewall_lists', name]
        desired.update(task_schedule.render('firewalllists', name, 'op', argv, schedule))
    return desired


class Manager:
    def __init__(self, directory='/config/firewall/lists'):
        self.directory = Path(directory)
        self.refresh_lock = threading.Lock()

    def read(self, name, default=None):
        try:
            value = json.loads((self.directory / name).read_text())
            if not isinstance(value, dict):
                raise ValueError('expected a JSON object')
            return value
        except FileNotFoundError:
            return {} if default is None else default
        except (OSError, ValueError) as error:
            report(f'Cannot read firewall list {name}: {error}; cache unavailable', warning=True)
            return {} if default is None else default

    def write(self, name, data):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_json(self.directory / name, data, mode=0o600)

    def checkpoint(self, state_directory, *, recovery=False):
        """Pin the imported before-image against existing configd transaction journals."""
        pins = self.read('rollback.json')
        active = {}
        new_transaction = False
        for name in ('transaction', 'confirmed'):
            path = Path(state_directory) / (name + '.json')
            if not path.exists():
                continue
            journal = json.loads(path.read_text())
            token = digest({key: journal[key] for key in ('before', 'id', 'owner') if key in journal})
            active[name] = pins.get(name, {})
            changed = active[name].get('token') != token
            if name == 'transaction':
                new_transaction = changed
            if changed or (name == 'confirmed' and new_transaction):
                active[name] = {'token': token, 'cache': self.read('cache.json')}
        if not recovery:
            self.write('rollback.json', active)
        for name in ('transaction', 'confirmed'):
            if recovery and name in active:
                return active[name]['cache']
        return self.read('cache.json')

    def collect(self, configuration, cache, *, refresh=(), output=None, recovery=False):
        selections = groups(configuration)
        updated = {}
        jobs = []
        for identity, definition in selections.items():
            group_key = '/'.join(identity)
            previous = cache.get(group_key, {})
            # Structural settings affect parsing, including protocol/field and dynamic restrictions.
            structure = {key: value for key, value in definition.items() if key != attachment_node(identity[0])}
            constraints = digest(lookup(configuration, ('firewall', identity[1]), {})) if identity[0] == 'map' else ''
            records = {}
            for attachment, options in definition[attachment_node(identity[0])].items():
                signature = digest([structure, options['source'], options.get('column', {})])
                old = previous.get(attachment, {})
                compatible = old.get('signature') == signature
                records[attachment] = old if compatible else {'signature': signature, 'entries': {}}
                if compatible and old.get('constraints', '') != constraints and 'text' in old:
                    # Recheck cached CSV jumps when their targets or calling hooks change,
                    # without another download or changing the rollback snapshot.
                    parsed = parse(old['text'].encode(), identity, definition, options, configuration,
                                   lambda message: report(f'{group_key} {attachment}: {message}', output, warning=True))
                    records[attachment] = old | parsed | {'constraints': constraints}
                if not recovery and (not compatible or (*identity, attachment) in refresh):
                    jobs.append((identity, definition, attachment, options, records, signature, constraints))
                elif not compatible:
                    report(f'{group_key} {attachment}: no compatible cache; using empty membership', output, warning=True)
            updated[group_key] = records

        def retrieve(job):
            identity, definition, attachment, options, records, signature, constraints = job
            label = '/'.join(identity) + ' ' + attachment
            warnings = []
            started = time.monotonic()
            old = records[attachment]
            try:
                data = fetch(options['source'])
                checksum = hashlib.sha256(data).hexdigest()
                if old.get('hash') == checksum:
                    result = old if not old.get('error') else old | {'error': None}
                    message = 'unchanged file; retained membership'
                else:
                    result = parse(data, identity, definition, options, configuration, warnings.append)
                    result.update(signature=signature, hash=checksum, checked=datetime.now(timezone.utc).isoformat(),
                                  error=None, constraints=constraints, text=data.decode('utf-8-sig', errors='replace'))
                    message = ', '.join(f'{key}={value}' for key, value in result['counts'].items())
            except (OSError, ValueError, csv.Error) as error:
                message = f'{error}; using cached membership' if old.get('hash') else f'{error}; using empty membership'
                warnings.append(message)
                result = old | {'error': str(error), 'checked': datetime.now(timezone.utc).isoformat()}
            return records, attachment, result, label, warnings, f'{message}; {time.monotonic() - started:.2f}s'

        if jobs:
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                for records, attachment, result, label, warnings, summary in pool.map(retrieve, jobs):
                    records[attachment] = result
                    for warning in warnings:
                        report(label + ': ' + warning, output, warning=True)
                    report(label + ': ' + summary, output)
        return updated

    def prepare(self, configuration, context, rebuild):
        selections = groups(configuration)
        if not selections and not self.directory.exists():
            return '', None
        before = self.checkpoint(context.state_directory, recovery=context.recovery)
        cache = self.collect(configuration, before, output=context.report, recovery=context.recovery)
        statements = []
        for identity, definition in selections.items():
            if object_id(identity) in rebuild:
                text, count = elements(identity, definition, cache['/'.join(identity)],
                                       lambda message: report(message, context.report, warning=True))
                statements.append(text)
                report(f'{"/".join(identity)}: prepared {count} unique elements', context.report)
        return ''.join(statements), cache

    def publish(self, cache):
        if cache is not None:
            try:
                self.write('cache.json', cache)
            except OSError as error:
                raise RecoveryError('Firewall membership loaded but its cache could not be published') from error

    @staticmethod
    def ready(engine):
        if engine.unhealthy or engine.busy:
            raise BusyError('A commit or recovery is in progress; retry the list update afterward')

    def update(self, engine, kind=None, family='', name=None, attachment=None, *, schedule=None):
        access.require_role('net-admin')
        # Identical schedules share one batch. Different schedules that happen to
        # coincide wait outside the engine lock, rather than losing an entire run.
        if not self.refresh_lock.acquire(blocking=schedule is not None):
            raise BusyError('A firewall list update is already in progress')
        messages = []
        output = lambda message: messages.append(str(message).rstrip('\n') + '\n')
        try:
            with engine.mutex:
                self.ready(engine)
                running = deepcopy(engine.running)
                configuration = engine.schema.defaults(running)
                selected = set()
                for identity, definition in groups(configuration).items():
                    if kind is not None and identity != (kind, family, name):
                        continue
                    for source, options in definition[attachment_node(identity[0])].items():
                        if attachment is not None and source != attachment:
                            continue
                        if schedule is not None and schedule_name(options) != schedule:
                            continue
                        selected.add((*identity, source))
                if not selected:
                    raise ValidationError('No matching firewall list attachments configured')
                before = self.checkpoint(engine.store.directory)
            report(('scheduled' if schedule is not None else 'manual') + f' refresh: {len(selected)} attachment(s)', output)
            after = self.collect(configuration, before, refresh=selected, output=output)
            with engine.mutex:
                access.require_role('net-admin')
                self.ready(engine)
                if running != engine.running:
                    raise BusyError('Configuration changed during retrieval; retry the list update')
                statements = []
                counts = {}
                for identity, definition in groups(configuration).items():
                    key = '/'.join(identity)
                    old = before.get(key, {})
                    records = after[key]
                    if {name: value.get('hash') for name, value in records.items()} == {name: value.get('hash') for name, value in old.items()}:
                        continue
                    text, count = elements(identity, definition, records,
                                           lambda message: report(message, output, warning=True))
                    statements.append(text)
                    counts[key] = count
                if statements:
                    nftables.manager.apply(''.join(statements), engine.store.directory, owner='firewall-lists')
                if after != before:
                    self.publish(after)
                for key, count in counts.items():
                    report(f'{key}: installed {count} unique elements', output)
                report(f'Refresh complete; replaced membership in {len(statements)} group(s)', output)
            return {'text': ''.join(messages)}
        except (RouterError, OSError) as error:
            if isinstance(error, RecoveryError):
                engine.unhealthy = True
            report(f'Refresh failed: {error}', output, warning=True)
            raise
        finally:
            self.refresh_lock.release()


manager = Manager()


def main():
    import argparse
    from nvyr.protocol import Client

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('schedule')
    arguments = parser.parse_args()
    with closing(Client('/run/nvyr/configd.sock')) as client:
        result = client.request('firewall-list-update', **vars(arguments))
    print(result['text'], end='')


if __name__ == '__main__':
    main()
