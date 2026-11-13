"""MPLS input membership and label-table capacity, owned by netlinkd."""

from nvyr.helpers import interfaces
from nvyr.tree import lookup


def get_config(context):
    return lookup(context.effective, ('protocols', 'mpls'), None)


def verify(configuration, context):
    pass


def generate(configuration, context):
    if configuration is None:
        return {'interfaces': [], 'label-table-size': 0}

    return {'interfaces': sorted(lookup(configuration, ('interface',), ())),
            'label-table-size': int(configuration['label-table-size'])}


def apply(generated, context):
    interfaces.manager.request('replace-mpls', values=generated)
