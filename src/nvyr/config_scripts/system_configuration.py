"""Configuration management settings owned by configd itself.

History pruning happens at Engine._persist's durable publication boundary, not
during apply: another owner or publication can still fail after this lifecycle.
"""

from nvyr.tree import lookup


def get_config(context):
    return lookup(context.effective, context.root, {})


def verify(configuration, context):
    # The schema validates individual configuration-management settings.
    pass


def generate(configuration, context):
    return configuration


def apply(configuration, context):
    # No external service to configure. Configd consumes the published settings.
    pass
