#!/usr/bin/env python3
"""Refresh external firewall group attachments."""

from contextlib import closing

from nvyr import opmode
from nvyr.protocol import Client


@opmode.command
def update(kind: str, family: str = '', name: str = '', attachment: str = None):
    with closing(Client('/run/nvyr/configd.sock')) as client:
        result = client.request('firewall-list-update', kind=kind, family=family,
                                name=name, attachment=attachment)
    print(result['text'], end='')


if __name__ == '__main__':
    opmode.run()
