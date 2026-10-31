"""Read image identity shared by operational commands; never manufacture a build date."""

from datetime import datetime
from importlib.metadata import PackageNotFoundError, version as package_version
import json
from pathlib import Path

from nvyr.errors import RouterError


METADATA_PATH = Path('/usr/share/nvyr/build.json')
LICENSE_PATH = Path('/usr/share/doc/nvyr-router/LICENSE')
COPYRIGHT = 'Copyright (c) 2026 L0crian and nVyR contributors'
PROJECT_URL = 'https://github.com/l0crian1/nVyR'


def read(path=None):
    """Return stored image metadata, preserving any additional fields for callers."""
    path = Path(path) if path is not None else METADATA_PATH

    try:
        document = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        # A wheel/development installation is not an ISO build. Package metadata
        # can identify its version, but installation time is not an image date.
        try:
            version = package_version('nvyr-router')
        except PackageNotFoundError:
            version = 'unknown'

        return {'version': version, 'build_timestamp': None, 'built_by': None}
    except (OSError, UnicodeError, ValueError) as error:
        raise RouterError(f'Cannot read build metadata from {path}: {error}') from error

    try:
        if not isinstance(document, dict):
            raise ValueError('Expected a JSON object')

        version, timestamp = document['version'], document['build_timestamp']
        if not isinstance(version, str) or not version or not version.isprintable():
            raise ValueError('version must be a nonempty printable string')

        if not isinstance(timestamp, str):
            raise ValueError('build_timestamp must be a UTC timestamp')

        instant = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
        if instant.strftime('%Y-%m-%dT%H:%M:%SZ') != timestamp:
            raise ValueError('build_timestamp must use YYYY-MM-DDTHH:MM:SSZ')

        built_by = document.get('built_by')
        if built_by is not None and (
                not isinstance(built_by, str) or not built_by.strip() or not built_by.isprintable()):
            raise ValueError('built_by must be a nonempty printable string or null')
    except (KeyError, ValueError) as error:
        raise RouterError(f'Invalid build metadata in {path}: {error}') from error

    return document


def format_version(metadata):
    """Display image identity and project attribution without a table header."""
    # ISO manifest generation also imports read(), without runtime UI dependencies.
    from tabulate import tabulate

    timestamp = metadata['build_timestamp']
    date = timestamp.removesuffix('Z').replace('T', ' ') + ' UTC' if timestamp else 'unavailable'

    rows = [
        ('Version', metadata['version']),
        ('Build date', date),
        ('Built by', metadata.get('built_by') or 'Not specified'),
        ('Copyright', COPYRIGHT),
        ('Project', PROJECT_URL),
    ]
    return tabulate(rows, tablefmt='presto', disable_numparse=True) + '\n'


def read_license():
    """Read the packaged project license verbatim, including its copyright notice."""
    try:
        return LICENSE_PATH.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as error:
        raise RouterError(f'Cannot read the nVyR license from {LICENSE_PATH}: {error}') from error
