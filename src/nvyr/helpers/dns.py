"""System DNS aggregation and publication, called only by netlinkd's event loop."""

import ipaddress
import json
import logging
from pathlib import Path

from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.storage import atomic_json
from nvyr.helpers.template import render, write

log = logging.getLogger(__name__)


class Resolver:
    def __init__(self, directory, learned, *, boot, path='/run/nvyr-resolver/resolv.conf'):
        self.journal = Path(directory) / 'dns.json'
        self.path, self.learned = Path(path), learned
        self.published = None
        self.state = json.loads(self.journal.read_text()) if self.journal.exists() else {}

        if self.state and self.state.get('format') != 1:
            raise RouterError('Unsupported DNS journal format')

        if self.state.get('boot') != boot:
            # Only configd's saved configuration may supply intent on a new boot.
            self.state = {'format': 1, 'boot': boot, 'sources': []}
            self.save()

    def save(self):
        atomic_json(self.journal, self.state)

    def records(self, sources):
        """Retain the winning source for each server using the same resolver precedence."""
        static, learned = [], []

        for source in sources:
            try:
                static.append({'server': str(ipaddress.ip_address(source)), 'source': 'Static', 'interface': None})
            except ValueError:
                for value in self.learned(source):
                    learned.append({'server': str(ipaddress.ip_address(value)), 'source': 'DHCP', 'interface': source})

        # Keep static servers first, then interface/lease order. Canonical addresses
        # prevent alternate IPv6 spellings or shared leases from adding duplicates.
        unique = {}
        for record in static + learned:
            unique.setdefault(record['server'], record)

        return list(unique.values())

    def servers(self, sources):
        return [record['server'] for record in self.records(sources)]

    def publish(self, sources):
        records = self.records(sources)
        text = render('system/resolv.conf.j2', {'servers': [record['server'] for record in records]})
        if not self.path.exists() or self.path.read_text() != text:
            write(self.path, text, mode=0o644)

        self.published = records

    def observation(self):
        """Report the published file, never a proposed list after failed publication."""
        records = self.published
        if records is None:
            records = self.records(self.state['sources'])
        metadata = {record['server']: record for record in records}
        result = []

        for line in self.path.read_text().splitlines():
            fields = line.split()
            if fields and fields[0] == 'nameserver':
                server = str(ipaddress.ip_address(fields[1]))
                result.append(metadata.get(server, {'server': server, 'source': 'Unknown', 'interface': None}))

        return {'servers': result, 'pending': 'pending' in self.state}

    def replace(self, sources, *, recovery=False):
        # IPC shape only; CLI values are validated before generate().
        if not isinstance(sources, list) or any(not isinstance(value, str) for value in sources):
            raise ValidationError('DNS sources must be a list of strings')

        if 'pending' in self.state and not recovery:
            raise RecoveryError('DNS has an incomplete transaction; restart configd to recover')

        before = self.state['sources']
        self.state['pending'] = list(sources)
        self.save()

        try:
            self.publish(sources)
            self.state['sources'] = list(sources)
            self.state.pop('pending')
            self.save()
        except Exception as error:
            self.state.update(sources=before, pending=list(sources))

            if recovery:
                try:
                    self.save()
                except Exception:
                    log.exception('Could not persist failed DNS recovery')

                raise RecoveryError(f'DNS recovery failed: {error}') from error

            try:
                self.publish(before)
                self.state.pop('pending')
                self.save()
            except Exception as rollback:
                self.state['pending'] = list(sources)

                try:
                    self.save()
                except Exception:
                    log.exception('Could not persist failed DNS rollback')

                raise RecoveryError(f'DNS apply failed ({error}); rollback failed ({rollback}); restart configd to recover') from rollback

            raise RouterError(f'DNS apply failed; previous configuration restored: {error}') from error

    def reconcile(self):
        if 'pending' not in self.state:
            self.publish(self.state['sources'])
