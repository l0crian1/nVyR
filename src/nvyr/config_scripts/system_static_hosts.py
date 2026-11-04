"""Publish operator-defined hostnames alongside local and DHCP host entries."""

from nvyr.helpers import dhcp_hosts
from nvyr.helpers.verification import require_fields
from nvyr.tree import lookup


HOSTS_PATH = '/etc/hosts'


def get_config(context):
    return lookup(context.effective, ('system', 'static-host-mapping'), {})


def verify(configuration, context):
    for hostname, mapping in configuration.items():
        # Each hosts-file entry needs an address for the canonical name and its aliases.
        require_fields(mapping, ('address',), f'system static-host-mapping {hostname}')


def generate(configuration, context):
    lines = []
    for hostname, mapping in sorted(configuration.items()):
        names = [hostname, *lookup(mapping, ('alias',), ())]
        fields = ' '.join(name.removesuffix('.') for name in names)
        for address in mapping['address']:
            lines.append(f'{address}\t{fields}\n')
    return ''.join(lines)


def apply(section, context):
    dhcp_hosts.reconcile(hosts_path=HOSTS_PATH, static_section=section)
