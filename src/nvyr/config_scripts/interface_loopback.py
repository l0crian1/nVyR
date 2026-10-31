"""Configure addresses and description on the permanent system loopback."""

from nvyr.helpers import interfaces
from nvyr.helpers.netlink import normalize
from nvyr.tree import lookup

ROOT = ('interfaces', 'loopback')


def get_config(context):
    return lookup(context.effective, ROOT, {})


def link_definitions(configuration):
    """Prepare loopback definitions for read-only preflight and application."""
    definitions = {}
    for name, link in interfaces.settings(configuration).items():
        attributes = {} if link.description is None else {'description': link.description}
        definitions[name] = {'kind': 'loopback', 'addresses': list(link.addresses),
                             'attributes': attributes}

    return definitions


def verify(configuration, context):
    # Driver validation also protects the fixed loopback identity and system prefixes.
    definitions = normalize(link_definitions(configuration))

    # Validate live ownership before apply, including during commit check.
    interfaces.manager.request('validate', owner='loopback', links=definitions,
                               recovery=context.recovery)


def generate(configuration, context):
    return link_definitions(configuration)


def apply(definitions, context):
    interfaces.manager.replace('loopback', definitions, recovery=context.recovery)
