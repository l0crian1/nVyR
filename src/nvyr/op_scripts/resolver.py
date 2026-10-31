#!/usr/bin/env python3
"""Show published system resolvers and perform bounded DNS lookups."""

import ipaddress
import json
import time

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename
from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers.interfaces import interface_vrfs, manager
from nvyr.helpers.process import cmd


@opmode.command
def servers(raw: bool = False):
    """List only servers actually published by netlinkd, with their source provenance."""
    observation = manager.request('dns-status')
    devices = json.loads(cmd(['ip', '-j', '-d', 'link', 'show']))
    domains = interface_vrfs(devices)
    records = []

    for source in observation['servers']:
        record = dict(source)
        if source['interface']:
            record['vrf'] = domains.get(source['interface'])
        else:
            record['vrf'] = 'default' if source['source'] == 'Static' else None
        records.append(record)

    if raw:
        return json.dumps(dict(observation, servers=records))

    if records:
        rows = [[record['server'], record['source'], record['interface'] or '—', record['vrf'] or '—']
                for record in records]
        print(tabulate(rows, headers=['Server', 'Source', 'Interface', 'VRF'], disable_numparse=True))
    else:
        print('No system name servers published.')
    if observation['pending']:
        print('Warning: DNS configuration recovery is pending; showing the published servers.')
    if observation['error']:
        print('Warning: ' + observation['error'])


def query(name, record_type=None, server=None):
    """Query A/AAAA by default, or PTR for an IP literal, without shell parsing."""
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        address = None

    if address is not None:
        if record_type is not None and record_type.upper() != 'PTR':
            raise OperationalError('An IP address performs a reverse lookup; choose type ptr or omit type.')
        query_name = dns.reversename.from_address(str(address))
        types = ['PTR']
    else:
        try:
            query_name = dns.name.from_text(name)
            query_name.to_wire()
        except (dns.exception.DNSException, UnicodeError, ValueError) as error:
            raise OperationalError(f'Invalid DNS name: {error}') from None
        types = [record_type.upper()] if record_type else ['A', 'AAAA']

    try:
        client = dns.resolver.Resolver(configure=server is None)
        if server is not None:
            client.nameservers = [str(ipaddress.ip_address(server))]
        if not client.nameservers:
            raise OperationalError('No DNS servers configured. Specify server <address>.')
        client.timeout = 2
        client.lifetime = 5
    except (OSError, ValueError, dns.resolver.NoResolverConfiguration) as error:
        raise OperationalError(f'Cannot configure DNS lookup: {error}') from None

    records = []
    queries = []
    seen = set()

    for selected in types:
        started = time.monotonic()
        try:
            answer = client.resolve(query_name, selected, search=False, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            raise OperationalError(f'{name}: name does not exist (NXDOMAIN).') from None
        except dns.exception.Timeout:
            raise OperationalError(f'{name}: DNS server timeout while looking up {selected}.') from None
        except dns.resolver.NoNameservers as error:
            raise OperationalError(f'{name}: DNS servers could not answer {selected}: {error}') from None
        except (OSError, dns.exception.DNSException) as error:
            raise OperationalError(f'{name}: DNS lookup failed: {error}') from None

        elapsed = (time.monotonic() - started) * 1000
        queries.append({'type': selected, 'server': str(answer.nameserver), 'milliseconds': elapsed,
                        'status': 'answer' if answer.rrset is not None else 'no-data'})
        for rrset in answer.response.answer:
            for value in rrset:
                record = {'name': rrset.name.to_text(omit_final_dot=True),
                          'type': dns.rdatatype.to_text(rrset.rdtype), 'answer': value.to_text(), 'ttl': rrset.ttl}
                key = (record['name'], record['type'], record['answer'])
                if key not in seen:
                    records.append(record)
                    seen.add(key)

    return {'name': name, 'records': records, 'queries': queries}


@opmode.command
def lookup(line: str, raw: bool = False):
    """Use the operational schema to retain completions for type and server options."""
    options = {}

    def select(name):
        def record(value):
            if name in options:
                raise OperationalError(f'{name.replace("_", "-")} can only be specified once.')
            options[name] = value
            return []

        return record

    path, _ = opmode.command_arguments(line, {'type': select('record_type'), 'server': select('server')})
    result = query(path[1], **options)

    if raw:
        return json.dumps(result)
    if result['records']:
        rows = [[record['name'], record['type'], record['answer'], record['ttl']] for record in result['records']]
        print(tabulate(rows, headers=['Name', 'Type', 'Answer', 'TTL'], disable_numparse=True))
    for request in result['queries']:
        if request['status'] == 'no-data':
            print(f"No {request['type']} records for {result['name']}.")

    servers = list(dict.fromkeys(request['server'] for request in result['queries']))
    print()
    if len(servers) == 1:
        print('Server: ' + servers[0])
    else:
        for request in result['queries']:
            print(f"{request['type']} server: {request['server']}")
    print(f"Query time: {sum(request['milliseconds'] for request in result['queries']):.0f} ms")


if __name__ == '__main__':
    opmode.run()
