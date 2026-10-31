"""Local Linux users and roles through the normal configuration lifecycle."""

from nvyr.errors import ValidationError
from nvyr.helpers import accounts, developer_access
from nvyr.tree import lookup

ROOT = ('system', 'login', 'user')


def get_config(context):
    return {
        'current': lookup(context.effective, ROOT, {}),
        'previous': lookup(context.previous, ROOT, {}),
        'developer-enabled': developer_access.enabled(),
        'developer-disable-pending': developer_access.disable_pending(),
    }


def verify(configuration, context):
    """Validate usable managed accounts and preserve administrative access."""
    previous = configuration['previous']
    developer_enabled = configuration['developer-enabled']
    developer_disable_pending = configuration['developer-disable-pending']
    configuration = configuration['current']
    # Unmanaged account configuration has no lifecycle work to validate.
    if not configuration and not previous:
        return  # Existing development configurations may not manage accounts yet.

    for name, user in configuration.items():
        # A managed login needs both authorization and a usable credential field.
        if not lookup(user, ('role',), None) or not lookup(user, ('authentication', 'encrypted-password'), None):
            raise ValidationError(f'system login user {name}: role and password are required')

    # Removing the last administrator would prevent subsequent account management.
    if not any(user['role'] == 'sys-admin' or
               (user['role'] == 'dev-admin' and developer_enabled and not developer_disable_pending)
               for user in configuration.values()):
        raise ValidationError('At least one administrator with a usable password must remain configured')

    for name, user in configuration.items():
        # Boot may restore disabled developer records from durable configuration;
        # the account backend removes their Linux access. Live additions remain forbidden.
        if (user['role'] == 'dev-admin' and not developer_enabled and
                not context.startup and lookup(previous, (name,), None) != user):
            raise ValidationError('Developer accounts require developer access enabled during installation')

    # Existing OS accounts must belong to nVyR's recorded account identities.
    accounts.manager.verify(configuration, context.state_directory)


def generate(configuration, context):
    # Disabled developer records remain in configuration, but neither application
    # nor compensation may grant them Linux access after developer access is disabled.
    targets = {}
    for target in ('current', 'previous'):
        targets[target] = {name: user for name, user in configuration[target].items()
                           if user['role'] != 'dev-admin' or configuration['developer-enabled']}
    return targets


def apply(plan, context):
    accounts.manager.apply(plan['current'], plan['previous'],
                           context.state_directory, recovery=context.recovery)
