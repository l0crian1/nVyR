#!/usr/bin/env python3
"""Inspect deterministic CGN assignments without enumerating every subscriber."""

import ipaddress
import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import cgnat
from nvyr.op_scripts.services import running_configuration
from nvyr.op_scripts import firewall
from nvyr.schema import Schema
from nvyr.tree import lookup


def configuration():
    return Schema.bundled().defaults(running_configuration())


@opmode.command
def pools(*, name: str = None, raw: bool = False):
    config = configuration()
    definitions = lookup(config, (*cgnat.PATH, 'pool'), {})
    if name is not None and name not in definitions:
        raise OperationalError(f'CGN pool {name!r} is not configured')
    rows = []
    for pool_name, pool in definitions.items():
        if name is not None and name != pool_name:
            continue
        rules = [number for number, rule in cgnat.enabled(config) if rule['pool'] == pool_name]
        rows.append([pool_name, ', '.join(pool['public-address']), pool['port-range'], pool['block-size'],
                     cgnat.capacity(pool), ', '.join(rules) or '-', lookup(pool, ('description',), '')])
    if raw:
        return json.dumps(rows)
    print(tabulate(rows, headers=['Pool', 'Public addresses', 'Ports', 'Block size', 'Capacity', 'Rules', 'Description'],
                   disable_numparse=True) if rows else 'No CGN pools configured.')


@opmode.command
def rules(*, number: str = None, raw: bool = False):
    config = configuration()
    table = firewall._load_table(read_configuration=False)
    installed = {rule['number']: rule for rule in lookup(table, ('chains', cgnat.CHAIN, 'rules'), ()) if 'number' in rule}
    definitions = lookup(config, (*cgnat.PATH, 'rule'), {})
    if number is not None and number not in definitions:
        raise OperationalError(f'CGN rule {number} is not configured')
    rows = []
    for rule_number, rule in sorted(definitions.items(), key=lambda item: int(item[0])):
        if number is not None and rule_number != number:
            continue
        if 'disable' in rule:
            status = 'Disabled'
        elif rule_number in installed:
            status = 'Installed'
        else:
            status = 'Not installed'
        counters = lookup(installed, (rule_number, 'counter'), {})
        rows.append([rule_number, lookup(rule, ('vrf',), 'default'), lookup(rule, ('pool',), '-'),
                     rule['allocation-offset'], status, lookup(counters, ('packets',), '-'),
                     lookup(counters, ('bytes',), '-'), lookup(rule, ('description',), '')])
    if raw:
        return json.dumps(rows)
    print(tabulate(rows, headers=['Rule', 'VRF', 'Pool', 'Offset', 'State', 'Packets', 'Bytes', 'Description'],
                   disable_numparse=True) if rows else 'No CGN rules configured.')


def allocation_rows(config, *, subscriber=None, public=None, port=None, vrf=None):
    source = int(ipaddress.IPv4Address(subscriber)) if subscriber is not None else None
    target = int(ipaddress.IPv4Address(public)) if public is not None else None
    rows = []
    for number, rule in cgnat.enabled(config):
        domain = lookup(rule, ('vrf',), 'default')
        if vrf is not None and vrf != domain:
            continue
        for address, low, high, first, size in cgnat.segments(config, rule):
            if source is not None:
                if not first <= source < first + (high - low + 1) // size:
                    continue
                index = source - first
            else:
                if address != target or not low <= port <= high:
                    continue
                index = (port - low) // size
            start = low + index * size
            rows.append([number, domain, rule['pool'], str(ipaddress.IPv4Address(first + index)),
                         str(ipaddress.IPv4Address(address)), f'{start}-{start + size - 1}'])
    return rows


@opmode.command
def allocation(*, subscriber: str = None, public: str = None, port: int = None, vrf: str = None, raw: bool = False):
    if subscriber is None and (public is None or port is None):
        raise OperationalError('Specify a subscriber address or a public address and port')
    rows = allocation_rows(configuration(), subscriber=subscriber, public=public, port=port, vrf=vrf)
    if raw:
        return json.dumps(rows)
    print(tabulate(rows, headers=['Rule', 'VRF', 'Pool', 'Subscriber', 'Public address', 'Ports / ICMP IDs'],
                   disable_numparse=True) if rows else 'No configured allocation matches.')
    if rows:
        print('Configured allocations; existing connections may retain translations from an earlier configuration.')


if __name__ == '__main__':
    opmode.run()
