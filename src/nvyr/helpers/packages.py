"""Debian package inventory shared by operational output and completion."""

import os

from nvyr.errors import OperationalError
from nvyr.helpers.process import cmd


def inventory():
    """Read package identifiers, preserving architecture qualifiers and versions."""
    fields = '${binary:Package}\t${Version}\t${Architecture}\t${binary:Summary}\n'
    output = cmd(['dpkg-query', '-W', '-f=' + fields],
                 env=dict(os.environ, LC_ALL='C'), timeout=5)

    records = []
    for line in output.splitlines():
        if not line:
            continue

        columns = line.split('\t', 3)
        if len(columns) != 4:
            raise OperationalError('Invalid package inventory returned by dpkg-query.')

        name, version, architecture, description = columns
        records.append({'package': name, 'version': version,
                        'architecture': architecture, 'description': description})

    return sorted(records, key=lambda record: record['package'])
