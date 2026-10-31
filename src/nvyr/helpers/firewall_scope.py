"""Select a firewall configuration without losing interface/VRF context."""

from nvyr.tree import lookup


MAIN_TABLE = 'nvyr_filter'
FAILSAFE_TABLE = 'nvyr_filter_failsafe'
TABLES = (MAIN_TABLE, FAILSAFE_TABLE)


def failsafe(configuration):
    """Reuse firewall consumers with the fail-safe subtree and no main NAT rules."""
    scoped = dict(configuration)
    scoped['firewall'] = lookup(configuration, ('firewall', 'fail-safe'), {})
    scoped.pop('nat', None)
    return scoped


def for_table(configuration, table):
    if configuration is not None and table == FAILSAFE_TABLE:
        return failsafe(configuration)
    return configuration
