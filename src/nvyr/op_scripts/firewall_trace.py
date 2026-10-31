#!/usr/bin/env python3
"""Monitor selected firewall packets, optionally saving timed JSON Lines captures."""

import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.helpers import firewall_trace
from nvyr.helpers import firewall_trace_analysis, firewall_trace_output
from nvyr.helpers.validators import duration_seconds
from nvyr.errors import OperationalError


@opmode.command
def monitor(line: str):
    """Observe traces until Ctrl+C or a deadline; leave tracing rules unchanged."""
    options = {}

    def duration(value):
        options['duration'] = duration_seconds(value)
        return []

    def save(value):
        options['save'] = value
        return []

    opmode.command_arguments(line, {'duration': duration, 'save': save})
    raise SystemExit(firewall_trace.monitor(**options))


@opmode.command
def show(line: str, raw: bool = False):
    """List persistent captures or explain selected packet journeys without current-rule guesses."""
    options = {}

    def select(name):
        def receive(value):
            if name in options:
                raise OperationalError(f'{name} can only be specified once.')
            options[name] = value
            return []
        return receive

    def family(name):
        def receive(value):
            if 'family' in options:
                raise OperationalError('Choose only one of ipv4 and ipv6.')
            options['family'] = name
            return []
        return receive

    mapping = {name: select(name) for name in ('id', 'detail', 'protocol', 'source-address',
               'destination-address', 'source-port', 'destination-port', 'verdict', 'hook', 'path')}
    mapping.update(ipv4=family('ipv4'), ipv6=family('ipv6'))
    path, _ = opmode.command_arguments(line, mapping)
    if len(path) == 3:
        if options:
            raise OperationalError('Select a capture file before applying trace filters.')
        captures = []
        directory = firewall_trace.DIRECTORY
        if directory.is_symlink():
            raise OperationalError('Trace directory must not be a symbolic link.')
        if directory.exists():
            for entry in sorted(directory.iterdir()):
                if entry.is_file() and not entry.is_symlink():
                    captures.append({'file': str(entry), 'bytes': entry.stat().st_size})
        if raw:
            return json.dumps(captures)
        print(tabulate([[row['file'], row['bytes']] for row in captures], headers=['Capture', 'Bytes'])
              if captures else 'No saved trace captures.')
        return

    identifier = options.pop('id', None)
    detail = options.pop('detail', False)
    report = firewall_trace_analysis.read(path[3], identifier=identifier, detail=detail or raw, filters=options)
    if raw:
        return json.dumps(report)
    print(firewall_trace_output.render(report, stories=identifier is not None, detail=detail))


if __name__ == '__main__':
    opmode.run()
