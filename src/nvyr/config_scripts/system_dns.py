"""System resolver sources; netlinkd alone publishes the resulting resolver file."""

from nvyr.helpers import interfaces
from nvyr.tree import lookup


def get_config(context):
    return lookup(context.effective, ('system', 'name-server'), ())


def verify(configuration, context):
    # Interface selectors may precede a lease or survive unplugging/removal.
    # Individual values are checked by the schema.
    pass


def generate(configuration, context):
    return list(configuration)


def apply(sources, context):
    interfaces.manager.request('replace-dns', sources=sources, recovery=context.recovery)
