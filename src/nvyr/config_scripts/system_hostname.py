"""Apply the system hostname through the normal commit and recovery lifecycle."""

from nvyr.helpers import system
from nvyr.tree import lookup


def get_config(context):
    return lookup(context.effective, ('system', 'host-name'), 'nvyr')


def verify(configuration, context):
    # Individual hostname constraints are enforced by the schema.
    pass


def generate(configuration, context):
    return configuration


def apply(hostname, context):
    system.apply_hostname(hostname)
