"""Resolve DNS-backed firewall sets on configuration and explicit manual updates."""

from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import threading

import dns.exception
import dns.resolver

from nvyr.errors import BusyError, RecoveryError, ValidationError
from nvyr.helpers import access, nftables
from nvyr.helpers.nftables_formatters import nft_singleton_name
from nvyr.storage import atomic_json


def groups(configuration):
    return configuration.get('firewall', {}).get('group', {}).get('domain-group', {})


def domains(definitions, name):
    """Union names while preserving each source group's configured lookup rounds."""
    result = {}
    pending = [name]
    visited = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        definition = definitions[current]
        rounds = int(definition.get('lookup', {}).get('rounds', '1'))
        for domain in definition.get('domain', ()):
            canonical = domain.lower().rstrip('.')
            result[canonical] = max(result.get(canonical, 0), rounds)
        pending.extend(definition.get('include-group', ()))
    return result


def verify(configuration):
    for family, definitions in groups(configuration).items():
        for name in definitions:
            # Empty DNS selectors otherwise create a silently nonmatching policy.
            if not domains(definitions, name):
                raise ValidationError(f'firewall group domain-group {family} {name}: '
                                      'at least one domain or nonempty include-group is required')


def queries(selections, selected=None):
    result = {}
    for family, definitions in selections.items():
        for name in definitions:
            if selected is not None and (family, name) not in selected:
                continue
            for domain, rounds in domains(definitions, name).items():
                key = family + ':' + domain
                result[key] = max(result.get(key, 0), rounds)
    return result


def members(definitions, name, family, cache):
    values = set()
    for domain in domains(definitions, name):
        values.update(cache.get(family + ':' + domain, {}).get('addresses', ()))
    return sorted(values, key=ipaddress.ip_address)


def elements(family, name, addresses):
    target = 'inet nvyr_filter ' + nft_singleton_name('domain-group', family, name)
    lines = ['flush set ' + target]
    if addresses:
        lines.append('add element ' + target + ' { ' + ', '.join(addresses) + ' }')
    return '\n'.join(lines) + '\n'


class Manager:
    def __init__(self, directory='/config/domain-groups'):
        self.directory = Path(directory)
        self.lock = threading.RLock()
        self.refresh_lock = threading.Lock()

    def read(self, report):
        try:
            cache = json.loads((self.directory / 'cache.json').read_text())
            for key, record in cache.items():
                version = {'ipv4': 4, 'ipv6': 6}[key.split(':', 1)[0]]
                if not isinstance(record['addresses'], list):
                    raise ValueError('cached addresses must be a list')
                for value in record['addresses']:
                    if not isinstance(value, str) or ipaddress.ip_address(value).version != version:
                        raise ValueError('cached address has the wrong family')
            return cache
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            report(f'Warning: Cannot read domain-group cache: {error}. Uncached domains will be empty if DNS is unavailable.\n')
            return {}

    def publish(self, cache, report):
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic_json(self.directory / 'cache.json', cache, mode=0o600)
        except OSError as error:
            report(f'Warning: Cannot save domain-group cache: {error}. Resolved addresses may be unavailable at reboot.\n')

    def resolve(self, requested, cache, report):
        """Collect successive answers; a DNS failure never replaces cached policy with emptiness."""
        result = {}
        try:
            resolver = dns.resolver.Resolver()
            resolver.cache = None
            resolver.lifetime = 3
        except (dns.exception.DNSException, OSError) as error:
            resolver = None
            setup_error = str(error)

        for key, rounds in requested.items():
            family, domain = key.split(':', 1)
            addresses = set()
            errors = []
            success = False
            for _ in range(rounds):
                try:
                    if resolver is None:
                        raise OSError(setup_error)
                    answer = resolver.resolve(domain + '.', 'A' if family == 'ipv4' else 'AAAA',
                                              search=False, raise_on_no_answer=False)
                    addresses.update(str(ipaddress.ip_address(item.address)) for item in answer)
                    success = True
                except (dns.exception.DNSException, OSError) as error:
                    errors.append(str(error))
                    # An outage should not multiply its timeout by the configured round count.
                    break

            previous = cache.get(key, {})
            if errors:
                addresses.update(previous.get('addresses', ()))
                report(f'Warning: DNS lookup failed for {domain} ({family}): {errors[0]}. '
                       'Retaining cached addresses; uncached names may be empty.\n')
            now = datetime.now(timezone.utc).isoformat()
            result[key] = {
                'addresses': sorted(addresses, key=ipaddress.ip_address),
                'checked': now,
                'resolved': now if success and not errors else previous.get('resolved'),
                'error': errors[0] if errors else None,
            }
        return result

    def prepare(self, configuration, context, rebuild):
        """Return membership statements and a cache to publish only after the firewall loads."""
        selections = groups(configuration)
        selected = {(family, name) for family, definitions in selections.items() for name in definitions
                    if ('set', nft_singleton_name('domain-group', family, name)) in rebuild}
        if not selected:
            return '', None
        with self.lock:
            cache = self.read(context.report)
        requested = queries(selections, selected)
        missing = {key: rounds for key, rounds in requested.items() if key not in cache}
        for key in requested.keys() - missing.keys():
            if cache[key].get('error'):
                context.report(f'Warning: Using cached DNS membership for {key}; '
                               f'last lookup failed: {cache[key]["error"]}. Run update firewall domain-group to retry.\n')
        if context.recovery:
            for key in missing:
                context.report(f'Warning: No cached DNS addresses for {key}; domain-group membership will be empty. '
                               'Run update firewall domain-group after DNS becomes available.\n')
        else:
            cache.update(self.resolve(missing, cache, context.report))
        lines = []
        for family, name in sorted(selected):
            lines.append(elements(family, name, members(selections[family], name, family, cache)))
        return ''.join(lines), cache

    @staticmethod
    def ready(engine):
        if engine.unhealthy or engine.busy:
            raise BusyError('A commit, rollback or recovery is in progress; retry the domain-group update afterward')

    def update(self, engine, family=None, name=None):
        """Refresh selected DNS names, allowing only one manual refresh at a time.

        Resolution occurs outside the engine mutex. Before applying membership,
        recheck configuration and engine activity under the lock; refresh shared
        consumers too, and publish the cache only after nftables succeeds.
        """
        access.require_role('net-admin')
        if family not in (None, 'ipv4', 'ipv6') or (name is not None and family is None):
            raise ValidationError('Select ipv4 or ipv6 before a domain-group name')
        if not self.refresh_lock.acquire(blocking=False):
            raise BusyError('A domain-group update is already in progress')
        try:
            return self._update(engine, family, name)
        finally:
            self.refresh_lock.release()

    def _update(self, engine, family, name):
        messages = []
        with engine.mutex:
            self.ready(engine)
            selections = deepcopy(groups(engine.running))
            selected = {(af, group) for af, definitions in selections.items() for group in definitions
                        if (family is None or af == family) and (name is None or group == name)}
            if name is not None and not selected:
                raise ValidationError(f'Domain-group {family} {name!r} is not configured')
            if not selected:
                return {'text': 'No domain-groups configured.\n'}
            with self.lock:
                cache = self.read(messages.append)

        # DNS runs outside the engine lock. Recheck state before touching nftables.
        resolved = self.resolve(queries(selections, selected), cache, messages.append)
        with engine.mutex, self.lock:
            access.require_role('net-admin')
            self.ready(engine)
            if selections != groups(engine.running):
                raise BusyError('Domain-group configuration changed during resolution; retry the update')
            current = self.read(messages.append)
            updated = current | resolved
            changes = []
            for af, definitions in selections.items():
                for group in definitions:
                    before = members(definitions, group, af, current)
                    after = members(definitions, group, af, updated)
                    # Refresh including parents and other groups sharing these DNS names.
                    if before != after:
                        changes.append(elements(af, group, after))
            if changes:
                try:
                    nftables.manager.apply(''.join(changes), engine.store.directory, owner='domain-groups')
                except RecoveryError:
                    engine.unhealthy = True
                    raise
            self.publish(updated, messages.append)
            messages.append(f'Domain-group lookup completed; refreshed {len(changes)} sets.\n')
            return {'text': ''.join(messages)}

    def status(self, engine, family=None, name=None):
        access.require_role('read-only')
        with engine.mutex, self.lock:
            messages = []
            cache = self.read(messages.append)
            rows = []
            for af, definitions in groups(engine.running).items():
                for group in definitions:
                    if (family is not None and af != family) or (name is not None and group != name):
                        continue
                    for domain in sorted(domains(definitions, group)):
                        record = cache.get(af + ':' + domain, {})
                        rows.append({'family': af, 'group': group, 'domain': domain, **record})
            return {'domains': rows, 'warnings': messages}


manager = Manager()
