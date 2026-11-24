#!/usr/bin/env python3
"""Display native LLDP observations and watch neighbor changes."""

import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.helpers import lldp
from nvyr.helpers.strip_private import strip_ip, strip_mac, strip_text, strip_value
from nvyr.helpers.process import run


def value(record, key):
    return ', '.join(str(item.get('value', item.get(key, '-'))) for item in record.get(key, ())) or '-'


def masked_document(value, mode, field=''):
    """lldpd JSON0 stores TLV values beside their subtype and metadata."""
    if isinstance(value, list):
        return [masked_document(item, mode, field) for item in value]
    if isinstance(value, dict):
        return {key: item if field == 'interface' and key == 'name'
                else masked_document(item, mode, field if key == 'value' else key)
                for key, item in value.items()}
    if not isinstance(value, str):
        return value
    if field == 'mgmt-ip':
        return strip_ip(value, mode)
    if field == 'id':
        if len(value.split(':')) == 6 and all(len(part) == 2 for part in value.split(':')):
            return strip_mac(value, mode)
        if strip_ip(value, 'all') != value:
            return strip_ip(value, mode)
        return strip_value(value, mode)
    if field in {'name', 'descr', 'serial', 'asset', 'asset-tag', 'location'}:
        return strip_value(value, mode)
    return strip_text(value, mode)


@opmode.command
def show(kind: str, interface: str = '', detail: bool = False, raw: bool = False, strip_private: str = None):
    arguments = ['show', 'chassis' if kind == 'local' else kind]
    if interface:
        arguments.extend(['ports', interface])
    if kind != 'statistics':
        arguments.append('details')

    if (detail or kind == 'local') and not strip_private:
        output = lldp.control(*arguments, raw=raw)
        return json.dumps(output) if raw else output

    document = lldp.control(*arguments, raw=True)
    if strip_private:
        # Keep the local interface label. Names within chassis/port TLVs identify the peer.
        document = masked_document(document, strip_private)
        if detail or kind == 'local':
            return json.dumps(document, indent=None if raw else 2)
    if raw:
        return json.dumps(document)

    rows = []
    for group in document.get('lldp', ()):
        for port in group.get('interface', ()):
            row = {'Interface': port['name']}
            if kind == 'statistics':
                for field, label in (('tx', 'Sent'), ('rx', 'Received'),
                                     ('rx_discarded_cnt', 'Discarded'),
                                     ('rx_unrecognized_cnt', 'Unrecognized TLVs'),
                                     ('ageout_cnt', 'Expired'), ('insert_cnt', 'Added'),
                                     ('delete_cnt', 'Deleted')):
                    row[label] = value(port, field)
            else:
                chassis = next(iter(port.get('chassis', ())), {})
                remote = next(iter(port.get('port', ())), {})
                if kind == 'interfaces':
                    row['Mode'] = value(port, 'status')
                else:
                    row['System'] = value(chassis, 'name')
                    row['Chassis ID'] = value(chassis, 'id')
                row['Port ID'] = value(remote, 'id')
                row['Description'] = value(remote, 'descr')
                row['Management address'] = value(chassis, 'mgmt-ip')
            rows.append(row)

    return (tabulate(rows, headers='keys', disable_numparse=True) + '\n'
            if rows else f'No LLDP {kind} to display.\n')


@opmode.command
def monitor(interface: str = ''):
    # Check service availability before handing the connection to the native watcher.
    lldp.control('show', 'configuration')
    arguments = ['lldpcli', '-u', str(lldp.SOCKET), 'watch']
    if interface:
        arguments.extend(['ports', interface])
    run([*arguments, 'details'], stream=True, timeout=None)


if __name__ == '__main__':
    opmode.run()
