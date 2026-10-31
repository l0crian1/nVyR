#!/usr/bin/env python3
"""Operate DB-IP country groups through configd's serialized runtime interface."""

from tabulate import tabulate

from nvyr import opmode
from nvyr.helpers.firewall_scope import FAILSAFE_TABLE
from nvyr.protocol import Client


def request(operation):
    client = Client('/run/nvyr/configd.sock')
    try:
        return client.request(operation)
    finally:
        client.close()


@opmode.command
def update():
    print(request('geoip-update')['text'], end='')


@opmode.command
def show():
    result = request('geoip-status')
    active = result['active'] or {}
    downloaded = result['downloaded'] or {}
    check = result['check'] or {}
    print(tabulate([
        ('Applied release', active.get('release', 'None')),
        ('Downloaded release', downloaded.get('release', 'None')),
        ('CSV SHA-1', active.get('sha1', 'None')),
        ('Last applied (UTC)', active.get('applied', 'Never')),
        ('Last checked (UTC)', check.get('time', 'Never')),
        ('Last update error', check.get('error') or 'None'),
        ('Schedule', 'Daily at midnight (router timezone)'),
    ], tablefmt='presto'))
    print()
    if result['groups']:
        rows = [('Fail-safe' if item['table'] == FAILSAFE_TABLE else 'Main',
                 item['family'].replace('ip', 'IP'), item['name'], ', '.join(item['countries']))
                for item in result['groups']]
        print(tabulate(rows, headers=['Firewall', 'Family', 'Address-group', 'Countries']))
        print()
    print(result['attribution'])


if __name__ == '__main__':
    opmode.run()
