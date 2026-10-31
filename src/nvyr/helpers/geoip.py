"""Download DB-IP Country Lite and atomically refresh configured address groups.

The provider hash describes the uncompressed CSV. Downloaded generations are
immutable; per-table active metadata advances only after the kernel accepts it.
"""

import csv
from datetime import datetime, timezone
import gzip
import hashlib
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
from urllib.error import URLError
from urllib.request import Request, urlopen
import zlib

from nvyr.errors import BusyError, OperationalError, RecoveryError
from nvyr.helpers import access, firewall_scope, geoip_config, nftables
from nvyr.helpers.nftables_formatters import nft_singleton_name
from nvyr.storage import atomic_json, sync_directory


PAGE = 'https://db-ip.com/db/download/ip-to-country-lite'
DOWNLOAD = re.compile(r'https://download\.db-ip\.com/free/dbip-country-lite-(\d{4}-\d{2})\.csv\.gz')
MAX_DOWNLOAD = 32 * 1024 * 1024
MAX_CSV = 128 * 1024 * 1024
MAX_ROWS = 2_000_000
ATTRIBUTION = 'IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0'


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class DownloadPage(HTMLParser):
    """Read the CSV card's published checksum and link, never the MMDB card."""

    def __init__(self):
        super().__init__()
        self.tag = None
        self.text = ''
        self.label = None
        self.fields = {}
        self.releases = []

    def handle_starttag(self, tag, attrs):
        if tag == 'dl':
            self.fields = {}
        if tag in ('dt', 'dd'):
            self.tag, self.text = tag, ''
        if tag == 'a':
            url = dict(attrs).get('href', '')
            match = DOWNLOAD.fullmatch(url)
            checksum = self.fields.get('SHA1SUM', '')
            if match and self.fields.get('Format') == 'CSV' and re.fullmatch('[0-9a-f]{40}', checksum):
                self.releases.append({'release': match[1], 'sha1': checksum, 'url': url})

    def handle_data(self, data):
        if self.tag:
            self.text += data

    def handle_endtag(self, tag):
        if tag == self.tag:
            if tag == 'dt':
                self.label = self.text.strip()
            else:
                self.fields[self.label] = self.text.strip()
            self.tag = None


def fetch(url, destination, limit):
    """Bound both the request duration and accepted transfer size."""
    request = Request(url, headers={'User-Agent': 'nVyR-GeoIP/0.1'})
    deadline = time.monotonic() + 180
    with urlopen(request, timeout=30) as response:
        # Redirects must retain HTTPS and the expected provider host.
        if not response.url.startswith(('https://db-ip.com/', 'https://download.db-ip.com/')):
            raise OperationalError('DB-IP redirected to an unexpected download host')
        total = 0
        while block := response.read(64 * 1024):
            total += len(block)
            if total > limit or time.monotonic() > deadline:
                raise OperationalError('DB-IP download exceeds the supported size or duration')
            destination.write(block)


def read_rows(path, expected_hash, selections=None):
    """Validate a compressed generation and select only the requested countries."""
    selected = {} if selections is None else {key: [] for key in selections}
    by_country = {}
    for key, countries in (selections or {}).items():
        for country in countries:
            by_country.setdefault((key[0], country), []).append(key)

    digest = hashlib.sha1()
    length = count = 0
    families = set()
    with gzip.open(path, 'rb') as stream:
        while line := stream.readline(1025):
            length += len(line)
            count += 1
            if len(line) > 1024 or length > MAX_CSV or count > MAX_ROWS:
                raise OperationalError('DB-IP CSV exceeds the supported size')
            digest.update(line)
            row = next(csv.reader([line.decode('utf-8')], strict=True))
            if len(row) != 3 or row[2] not in geoip_config.COUNTRIES:
                raise OperationalError(f'Invalid DB-IP CSV record {count}')
            start, end = ipaddress.ip_address(row[0]), ipaddress.ip_address(row[1])
            if start.version != end.version or int(start) > int(end):
                raise OperationalError(f'Invalid DB-IP address range at record {count}')
            family = 'ipv' + str(start.version)
            families.add(family)
            for key in by_country.get((family, row[2]), ()):
                selected[key].append(str(start) if start == end else f'{start}-{end}')

    if digest.hexdigest() != expected_hash:
        raise OperationalError('DB-IP CSV checksum mismatch')
    if families != {'ipv4', 'ipv6'}:
        raise OperationalError('DB-IP CSV must contain both IPv4 and IPv6 records')
    return selected


def elements(selections, members, table='nvyr_filter'):
    """Keep flush and every insertion together in one nftables transaction."""
    lines = []
    for family, name in sorted(selections):
        native = nft_singleton_name('address-group', family, name)
        lines.append(f'flush set inet {table} {native}')
        values = members[family, name]
        # Splitting the input lines does not split the kernel transaction.
        for offset in range(0, len(values), 1000):
            body = ', '.join(values[offset:offset + 1000])
            lines.append(f'add element inet {table} {native} {{ {body} }}')
    return '\n'.join(lines) + '\n'


class Manager:
    def __init__(self, directory='/config/geoip'):
        self.directory = Path(directory)
        self.lock = threading.RLock()

    def metadata(self, name):
        path = self.directory / (name + '.json')
        if not path.exists():
            return None
        value = json.loads(path.read_text())
        if name in ('active', 'active-failsafe', 'downloaded'):
            if not re.fullmatch('[0-9a-f]{40}', value.get('sha1', '')):
                raise OperationalError('Invalid GeoIP cache metadata')
        return value

    def database(self, metadata):
        return self.directory / (metadata['sha1'] + '.csv.gz')

    def record(self, name, value):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_json(self.directory / (name + '.json'), value, mode=0o600)

    def download(self):
        """Check release metadata; reuse a fully verified download on retries."""
        with self.lock:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                with tempfile.TemporaryFile() as page:
                    fetch(PAGE, page, 1024 * 1024)
                    page.seek(0)
                    parser = DownloadPage()
                    parser.feed(page.read().decode('utf-8'))
                if len(parser.releases) != 1:
                    raise OperationalError('Cannot identify DB-IP CSV release/checksum; existing groups were retained')
                release = parser.releases[0]
                path = self.database(release)
                if not path.exists():
                    with tempfile.NamedTemporaryFile(dir=self.directory, delete=False) as stream:
                        temporary = Path(stream.name)
                        try:
                            fetch(release['url'], stream, MAX_DOWNLOAD)
                            stream.flush()
                            os.fsync(stream.fileno())
                            read_rows(temporary, release['sha1'])
                            os.replace(temporary, path)
                            sync_directory(self.directory)
                        finally:
                            temporary.unlink(missing_ok=True)
                self.record('downloaded', release)
                self.record('check', {'time': now(), 'error': None})
                return release
            except (OSError, EOFError, ValueError, csv.Error, zlib.error, URLError, OperationalError) as error:
                self.record('check', {'time': now(), 'error': str(error)})
                raise OperationalError(f'GeoIP update failed: {error}') from error

    def cached(self, *, recovery=False, report=print):
        metadata = self.metadata('active') or self.metadata('downloaded')
        if metadata is not None:
            return metadata

        if recovery:
            reason = 'GeoIP cache is missing'
        else:
            try:
                return self.download()
            except OperationalError as error:
                reason = str(error)

        report(f'Warning: {reason}. GeoIP address-groups will be empty until a successful update.\n')
        return None

    def publish(self, metadata, table='nvyr_filter'):
        try:
            name = 'active-failsafe' if table == firewall_scope.FAILSAFE_TABLE else 'active'
            self.record(name, metadata | {'applied': now()})
        except OSError as error:
            raise RecoveryError('GeoIP sets loaded but cache publication failed; restart configd to recover') from error

    def apply(self, rendered, context, rebuild, *, configuration=None, table='nvyr_filter',
              owner='firewall', check_only=False):
        configuration = context.effective if configuration is None else configuration
        groups = geoip_config.groups(configuration)
        selections = {key: countries for key, countries in groups.items()
                      if ('set', nft_singleton_name('address-group', *key)) in rebuild}
        accounting = 'connection-accounting' in configuration.get('firewall', {}).get('global-options', {})
        if not selections:
            nftables.manager.apply(rendered, context.state_directory, accounting=accounting,
                                   owner=owner, check_only=check_only)
            return

        with self.lock:
            metadata = self.cached(recovery=context.recovery, report=context.report)
            if table == firewall_scope.FAILSAFE_TABLE:
                metadata = self.metadata('downloaded') or metadata

            if metadata is None:
                members = {key: [] for key in selections}
            else:
                # Populate groups left empty by earlier commits before marking this table active.
                active_key = 'active-failsafe' if table == firewall_scope.FAILSAFE_TABLE else 'active'
                if self.metadata(active_key) is None:
                    selections = groups

                try:
                    members = read_rows(self.database(metadata), metadata['sha1'], selections)
                except (OSError, EOFError, ValueError, csv.Error, zlib.error) as error:
                    raise OperationalError(f'Cannot read GeoIP cache: {error}') from error

            nftables.manager.apply(rendered + '\n' + elements(selections, members, table),
                                   context.state_directory, accounting=accounting,
                                   owner=owner, check_only=check_only)
            if not check_only and metadata is not None:
                self.publish(metadata, table)

    def update(self, engine):
        access.require_role('net-admin')
        with engine.mutex:
            self.ready(engine)
            if not self.scopes(engine.running):
                return {'text': 'No GeoIP address-groups configured.\n'}

        # Never hold the engine lock while contacting DB-IP. A commit may proceed.
        release = self.download()
        with engine.mutex:
            access.require_role('net-admin')
            self.ready(engine)
            scopes = self.scopes(engine.running)
            if not scopes:
                return {'text': 'No GeoIP address-groups remain configured.\n'}
            if firewall_scope.FAILSAFE_TABLE in scopes and not nftables.manager.table_exists(firewall_scope.FAILSAFE_TABLE):
                del scopes[firewall_scope.FAILSAFE_TABLE]
            if not scopes:
                return {'text': f"GeoIP cache ready ({release['release']}); fail-safe firewall is not active.\n"}
            with self.lock:
                current = []
                for table in scopes:
                    key = 'active-failsafe' if table == firewall_scope.FAILSAFE_TABLE else 'active'
                    metadata = self.metadata(key)
                    current.append(metadata is not None and metadata['sha1'] == release['sha1'])
                if all(current):
                    return {'text': f"GeoIP is unchanged ({release['release']}); no sets updated.\n"}
                try:
                    updates = []
                    for table, selections in scopes.items():
                        members = read_rows(self.database(release), release['sha1'], selections)
                        updates.append(elements(selections, members, table))
                    nftables.manager.apply('\n'.join(updates), engine.store.directory, owner='geoip')
                    for table in scopes:
                        self.publish(release, table)
                except RecoveryError:
                    engine.unhealthy = True
                    raise
                except Exception as error:
                    self.record('check', {'time': now(), 'error': str(error)})
                    raise
                count = sum(len(selections) for selections in scopes.values())
                return {'text': f"GeoIP updated to {release['release']}; refreshed {count} address-groups.\n"}

    @staticmethod
    def scopes(configuration):
        selections = geoip_config.groups(configuration)
        return {firewall_scope.MAIN_TABLE: selections} if selections else {}

    @staticmethod
    def ready(engine):
        if engine.unhealthy:
            raise BusyError('GeoIP updates are unavailable until configuration recovery completes')
        if engine.busy:
            raise BusyError('A commit or rollback is in progress; retry the GeoIP update afterward')

    def status(self, engine):
        access.require_role('read-only')
        with engine.mutex, self.lock:
            return {'active': self.metadata('active'), 'downloaded': self.metadata('downloaded'),
                    'check': self.metadata('check'), 'attribution': ATTRIBUTION,
                    'groups': [{'family': family, 'name': name, 'countries': list(countries), 'table': table}
                               for table, selections in self.scopes(engine.running).items()
                               for (family, name), countries in sorted(selections.items())]}


manager = Manager()
