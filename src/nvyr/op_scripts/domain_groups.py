#!/usr/bin/env python3
"""Manually refresh DNS-backed groups and display cached lookup results."""

from contextlib import closing
from tabulate import tabulate

from nvyr import opmode
from nvyr.protocol import Client


@opmode.command
def update(family: str = None, name: str = None):
    with closing(Client('/run/nvyr/configd.sock')) as client:
        result = client.request('domain-group-update', family=family, name=name)
    print(result['text'], end='')


@opmode.command
def show(family: str = None, name: str = None):
    with closing(Client('/run/nvyr/configd.sock')) as client:
        result = client.request('domain-group-status', family=family, name=name)
    for warning in result['warnings']:
        print(warning, end='')
    rows = []
    for item in result['domains']:
        rows.append([item['family'].replace('ip', 'IP'), item['group'], item['domain'],
                     '\n'.join(item.get('addresses', ())) or 'None', item.get('resolved') or 'Never',
                     item.get('checked') or 'Never', item.get('error') or 'None'])
    if not rows:
        print('No domain-groups configured for this selection.')
        return
    print(tabulate(rows, headers=['Family', 'Group', 'Domain', 'Addresses',
                                 'Last resolved (UTC)', 'Last checked (UTC)', 'Error']))


if __name__ == '__main__':
    opmode.run()
