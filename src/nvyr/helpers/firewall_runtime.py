"""Clear learned firewall members against configd's authoritative running state."""

from nvyr import opmode
from nvyr.errors import BusyError, OperationalError
from nvyr.helpers import access
from nvyr.helpers.nftables_formatters import (
    NFT_KEYMAP, nft_group_fields, nft_learned_member, nft_match_group_name, nft_singleton_name,
)
from nvyr.helpers.process import rc_cmd
from nvyr.lexer import split_pipeline
from nvyr.schema import resolve_word
from nvyr.tree import lookup


COMMAND = ('firewall.nvyr.op', 'clear_group')
PREFIX = ('clear', 'firewall', 'group')


def _definition(configuration, path):
    kind, family, name = path[3:6]
    return lookup(configuration, ('firewall', 'group', kind, family, name), None)


def completion_candidates(cursor, state, candidates, configuration):
    """Only offer fields that participate in this running group's exact key."""
    path = cursor.path
    if path[:3] != PREFIX or len(path) < 7 or path[3] != 'match-group' or path[6] != 'member':
        return candidates

    definition = _definition(configuration, path)
    if definition is None or 'dynamic' not in definition:
        return []

    fields = nft_group_fields(definition)
    allowed = [NFT_KEYMAP[field].path or (field,) for field in fields]
    if cursor.expect != 'child':
        relative = path[7:]
        return candidates if relative in allowed else []

    result = []
    for name, description in candidates:
        if name == 'and':
            result.append((name, description))
            continue

        parent = state.input(name) if state is not None else cursor
        relative = parent.path[7:] + (name,)
        if any(field[:len(relative)] == relative for field in allowed):
            result.append((name, description))

    return result


def _request(schema, line):
    stages = split_pipeline(line)
    if len(stages) != 1:
        raise OperationalError('Group cleanup takes one command without pipe modifiers.')

    tokens = stages[0]
    if tokens and resolve_word(tokens[0].value, [*schema.root['children'], 'run']) == 'run':
        tokens = tokens[1:]

    cursor = schema.operational(tokens)
    command = cursor.node.get('command', {})
    if not isinstance(command, dict) or tuple(command.get('argv', ())[:2]) != COMMAND:
        raise OperationalError('Expected clear firewall group and a dynamic group.')

    path = cursor.path
    if path[:3] != PREFIX or len(path) != 7 or path[6] not in {'member', 'learned'}:
        raise OperationalError('Specify a learned member or learned to clear the group.')
    if cursor.expect in {'tag', 'value'}:
        raise OperationalError('Specify the exact learned member to remove.')

    values = {}
    if path[6] == 'member':
        if path[3] == 'address-group':
            values['source-address'] = cursor.value
        else:
            def capture(field):
                def argument(value):
                    if field in values:
                        raise OperationalError(f'Specify {" ".join(NFT_KEYMAP[field].path or (field,))} only once.')
                    values[field] = value
                    return []
                return argument

            mapping = {}
            for field, key in NFT_KEYMAP.items():
                if key.dynamic:
                    relative = key.path or (field,)
                    mapping[relative[0] if len(relative) == 1 else relative] = capture(field)

            opmode.command_arguments(line, mapping, schema=schema)

    return path, values, cursor


def complete_request(schema, line, configuration):
    """Offer execution only after the full configured runtime key is supplied."""
    path, values, _ = _request(schema, line)
    definition = _definition(configuration, path)
    if definition is None or 'dynamic' not in definition:
        return False
    if path[6] == 'learned':
        return True

    fields = ['source-address'] if path[3] == 'address-group' else nft_group_fields(definition)
    return set(values) == set(fields)


def clear(engine, schema, line):
    """Serialize cleanup with commits without acquiring a user's candidate lock."""
    access.require_role('net-admin')
    path, values, cursor = _request(schema, line)
    access.require_role(schema.minimum_access(cursor.node))
    for role in cursor.required_access:
        access.require_role(role)

    with engine.mutex:
        # A role can change while this request waits for another engine operation.
        access.require_role('net-admin')
        access.require_role(schema.minimum_access(cursor.node))
        for role in cursor.required_access:
            access.require_role(role)

        if engine.unhealthy:
            raise BusyError('Firewall cleanup is unavailable until configuration recovery completes.')
        if engine.busy:
            raise BusyError('A commit or rollback is in progress. Wait for it to finish, then try again.')

        definition = _definition(engine.running, path)
        kind, family, name, operation = path[3:]
        label = f'{family.replace("ip", "IP")} {kind} {name}'
        if definition is None:
            raise OperationalError(f'{label} is not configured in the running configuration.')
        if 'dynamic' not in definition:
            raise OperationalError(f'{label} is not dynamic. Configured members must be changed through configuration.')

        # Do not clear configured policy if an invalid definition reached running state.
        member_node = 'address' if kind == 'address-group' else 'entry'
        if definition.get(member_node):
            raise OperationalError(f'{label} contains configured members; remove them before clearing runtime state.')

        fields = ['source-address'] if kind == 'address-group' else nft_group_fields(definition)
        native = (nft_singleton_name(kind, family, name) if kind == 'address-group'
                  else nft_match_group_name(family, name))
        if operation == 'learned':
            argv = ['nft', 'flush', 'set', 'inet', 'nvyr_filter', native]
            message = f'Learned members cleared from {label}.'
        else:
            missing = set(fields) - values.keys()
            extra = values.keys() - set(fields)
            if missing or extra:
                required = ', '.join(' '.join(NFT_KEYMAP[field].path or (field,)) for field in fields)
                raise OperationalError(f'{label}: specify exactly these member fields: {required}.')

            for field, value in values.items():
                key = NFT_KEYMAP[field]
                address = field.endswith('-address')
                interval = key.interval or field in {'source-port', 'destination-port', 'packet-mark', 'dscp'}
                if (address and ('/' in value or '-' in value)) or (interval and '-' in value):
                    raise OperationalError(f'{field}: specify one exact value, not a prefix or range.')
                if field == 'tcp-flags' and any(flag.startswith('not ') for flag in value.split(',')):
                    raise OperationalError('tcp-flags: specify the flags present in the exact key, without not.')

            element = nft_learned_member(fields, values)
            # An expired or already cleared key is harmless; never broaden a missing-key delete.
            argv = ['nft', 'destroy', 'element', 'inet', 'nvyr_filter', native, '{', element, '}']
            message = f'Learned member cleared from {label} (if present).'

        status, output = rc_cmd(argv)
        if status:
            raise OperationalError(f'Cannot clear {label}: {output.strip() or "nftables cleanup failed."}')

    return {'text': message + '\n'}
