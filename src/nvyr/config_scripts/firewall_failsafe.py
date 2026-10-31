"""Install temporary boot protection with the shared firewall implementation."""

from nvyr.config_scripts import firewall
from nvyr.errors import ValidationError
from nvyr.helpers import firewall_scope, nftables, nftables_lifecycle, nftables_zones
from nvyr.tree import lookup


TABLE = firewall_scope.FAILSAFE_TABLE
ROOT = ('firewall', 'fail-safe')


def get_config(context):
    return firewall_scope.failsafe(context.effective)


def verify(configuration, context):
    try:
        firewall.verify(configuration, context)
    except ValidationError as error:
        # Shared checks report paths relative to the selected firewall tree.
        raise ValidationError(str(error).replace('firewall ', 'firewall fail-safe ')) from error


def lifecycle(configuration):
    """No dependency planner is needed when replacing the complete temporary table."""
    objects = nftables_lifecycle.object_paths(configuration)
    dispatch = nftables_lifecycle.entrypoints(configuration)
    zones = nftables_zones.maps(lookup(configuration, ('firewall',), {}))
    return {'remove': set(), 'rebuild': objects.keys() | dispatch.keys() | zones.keys()}


def generate(configuration, context):
    if lookup(context.effective, ROOT, None) is None:
        return f'destroy table inet {TABLE}\n'
    from nvyr.helpers import logging_runtime
    log_groups = {}
    if logging_runtime.groups(context.effective):
        log_groups = logging_runtime.nft_groups(context.effective, context.state_directory / 'logging', 'failsafe')
    return firewall.render_rules(configuration, lifecycle(configuration), table=TABLE,
                                  replace_table=True, log_groups=log_groups)


def apply(rendered, context):
    configured = lookup(context.effective, ROOT, None) is not None
    previous = lookup(context.previous_effective, ROOT, None) is not None
    if not configured and not previous:
        return

    # Ordinary rollback also uses recovery; it must not reactivate boot protection.
    active = context.startup or nftables.manager.table_exists(TABLE)
    if active:
        from nvyr.helpers import logging_runtime
        logging_runtime.prepare_groups(context.effective, context.state_directory / 'logging')
    configuration = get_config(context)
    accounting = 'connection-accounting' in lookup(configuration, ('firewall', 'global-options'), {})
    nftables.manager.apply(rendered, context.state_directory, owner='firewall_failsafe',
                           accounting=accounting, check_only=not active)
    from nvyr.helpers import logging_runtime
    logging_runtime.cleanup(context.effective, context.state_directory / 'logging', scope='failsafe')
