#!/usr/bin/env python3
"""Display installed firewall objects and clear their runtime state."""

import json
import re

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import firewall_scope, nftables_timeouts
from nvyr.helpers.nftables_formatters import (
    NFT_FILTER_HOOKS, nft_counter_group_name, nft_limit_group_name, nft_quota_group_name,
)
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.output import detailed_output
from nvyr.helpers.process import cmd, rc_cmd
from nvyr.helpers.strip_private import strip_ip, strip_mac, strip_value
from nvyr.protocol import Client


MISSING = '—'
RULE_HEADERS = ['Rule', 'Action', 'Packets', 'Bytes', 'Last used', 'Description']


def _load_table(*, read_configuration=True, failsafe=False):
    """Read installed objects once; running configuration supplies group column names."""
    configuration = None
    if read_configuration:
        try:
            client = Client('/run/nvyr/configd.sock')
            try:
                response = client.request('execute', text='show running-configuration')
            finally:
                client.close()
        except (OSError, EOFError) as error:
            raise OperationalError(f'Cannot read running configuration: {error}') from None

        try:
            configuration = json.loads(response['text'])
        except (ValueError, KeyError, TypeError) as error:
            raise OperationalError(f'Cannot interpret running configuration: {error}') from None

    try:
        document = json.loads(cmd(['nft', '-j', 'list', 'ruleset']))
        normalized = normalize(document, configuration=configuration)
    except (ValueError, KeyError, TypeError) as error:
        raise OperationalError(f'Cannot interpret firewall data: {error}') from None

    name = firewall_scope.FAILSAFE_TABLE if failsafe else firewall_scope.MAIN_TABLE
    return normalized['tables'].get('inet', {}).get(name, {})


def _label(field):
    acronyms = {'vlan': 'VLAN', 'id': 'ID', 'mac': 'MAC', 'icmp': 'ICMP', 'tcp': 'TCP', 'dscp': 'DSCP', 'ttl': 'TTL', 'gc': 'GC', 'fib': 'FIB'}
    words = field.replace('-', ' ').split()
    return ' '.join(acronyms.get(word, word.capitalize() if index == 0 else word)
                    for index, word in enumerate(words))


def _value(value, field, private):
    """Format and mask cells before tabulation, without changing the normalized data."""
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            if field in ('source-address', 'destination-address', 'source-mac', 'destination-mac'):
                text = _value(key, field, private)
                if 'mask' in item:
                    text += ' mask ' + _value(item['mask'], field, private)
            else:
                text = f'{key}: {_value(item, key, private)}'
            parts.append(text)
        return '\n'.join(parts) or 'Enabled'

    if isinstance(value, list):
        return ', '.join(_value(item, field, private) for item in value)
    if value is True:
        return 'Enabled'
    if value is None:
        return MISSING

    text = str(value)
    if field in ('tcp-flags', 'tcp_flag'):
        text = text.replace(',', ' and ')
    if not private or not text:
        return text
    if field in ('description', 'prefix'):
        return strip_value(text, private)
    if field in ('source-mac', 'destination-mac', 'mac', 'ether_addr'):
        return strip_mac(text, private)
    return strip_ip(text, private)


def _last_used(record):
    if 'last-used' not in record:
        return MISSING
    elapsed = record['last-used']
    if elapsed is None:
        return 'Never'
    return f'{elapsed:g}s ago'


def _action(record):
    if 'helper-map' in record:
        return 'assign helpers'
    if 'zone-dispatch' in record:
        return 'zone dispatch'
    if 'map' in record:
        return 'map ' + record['map']

    action = record.get('action', MISSING)
    target = record.get(action + '-target')
    return f'{action} {target}' if target else action


def _rule_row(rule, private):
    counter = rule.get('counter', {})
    action = _action(rule)
    if rule.get('unsupported'):
        action += ' [incomplete]'
    return [
        rule.get('number', MISSING), action,
        counter.get('packets', MISSING), counter.get('bytes', MISSING),
        _last_used(rule), _value(rule.get('description', ''), 'description', private),
    ]


def _rule_detail(rule, private):
    print(f"Rule {rule.get('number', MISSING)}\n")
    headers = ['Action']
    values = [_action(rule)]
    hidden = {'number', 'handle', 'comment', 'action', 'jump-target', 'goto-target',
              'offload-target', 'counter', 'last-used', 'unsupported', 'runtime-limits'}

    for field, value in rule.items():
        if field == 'not':
            for excluded_field, excluded_value in value.items():
                if excluded_field == 'match-group-fields':
                    continue
                headers.append(_label(excluded_field) + ' (not)')
                values.append(_value(excluded_value, excluded_field, private))
            continue
        if field not in hidden:
            headers.append(_label(field))
            values.append(_value(value, field, private))

    counter = rule.get('counter', {})
    if 'group' in counter:
        headers.append('Counter group')
        values.append(counter['group'])
    headers.extend(['Packets', 'Bytes', 'Last used'])
    values.extend([counter.get('packets', MISSING), counter.get('bytes', MISSING), _last_used(rule)])
    if rule.get('unsupported'):
        headers.append('Warning')
        values.append('Unsupported expressions: this display is incomplete.')
    detailed_output([values], headers)


def _section_heading(title):
    """Keep each independently rendered firewall table visually distinct."""
    print('=' * 72)
    print(title + '\n')


def _show_chain(title, chain, rule_number, private, detail):
    rules = chain.get('rules', [])
    if rule_number is not None:
        if not any(rule.get('number') == rule_number for rule in rules):
            raise OperationalError(f'Rule {rule_number} is not installed in {title}.')
        rules = [rule for rule in rules if rule.get('number') in (rule_number, 'default')]

    _section_heading(title)
    display_rules = []
    for rule in rules:
        # Base chains contain state policies, enrollment, and family dispatch.
        mapping = rule.get('verdict-map')
        if mapping and mapping['fields'] == ['state']:
            for entry in mapping['entries']:
                state_rule = dict(entry, **entry['result'])
                state_rule['number'] = ', '.join(str(value) for value in entry['key'])
                display_rules.append(state_rule)
        elif mapping and mapping['fields'] == ['address-family'] and not rule.get('unsupported'):
            continue
        else:
            display_rules.append(rule)

    if detail:
        for rule in display_rules:
            _rule_detail(rule, private)
        if not display_rules:
            print('No rules installed.\n')
        if any(rule.get('unsupported') for rule in rules):
            print('Warning: unsupported expressions are present; this display is incomplete.\n')
        return

    rows = [_rule_row(rule, private) for rule in display_rules]
    if rows:
        print(tabulate(rows, headers=RULE_HEADERS, disable_numparse=True,
                       colalign=('left', 'left', 'right', 'right', 'left', 'left')))
    else:
        print('No rules installed.')

    if any(rule.get('unsupported') for rule in rules):
        print('Warning: unsupported expressions are present; this display is incomplete.')
    print()


def _group_result(result, private):
    if 'action' in result:
        return _action(result)
    return _value(result, 'result', private)


def _show_timeout_group(objects, private, detail):
    """Show both native halves of an inet policy under its single public name."""
    first = objects[0]
    family, name = nftables_timeouts.identity(first['name'])
    title = family.replace('ip', 'IP') + ' timeout-group ' + name
    _section_heading(title)
    rows = []
    for group in objects:
        state_names = {native: public for public, (native, _)
                       in nftables_timeouts.STATES[group['protocol']].items()}
        for state, seconds in group['policy'].items():
            rows.append(['IPv4' if group['l3proto'] == 'ip' else 'IPv6', group['protocol'],
                         state_names.get(state, state.replace('_', '-')), f'{seconds}s',
                         _value(group.get('description', ''), 'description', private)])
    headers = ['Family', 'Protocol', 'State', 'Timeout', 'Description']
    if detail:
        detailed_output(rows, headers)
    else:
        print(tabulate(rows, headers=headers, disable_numparse=True))
        print()


def _show_named_state(group, private, detail):
    family = next((family for family in ('ipv4', 'ipv6', 'inet') if group['name'].startswith(family + '_')), None)
    title = ' '.join(part for part in (family.replace('ip', 'IP') if family else None,
                                      group['group-kind'], group['group-name']) if part)
    _section_heading(title)

    if group['group-kind'] == 'quota-group':
        headers = ['Mode', 'Allowance (bytes)', 'Used (bytes)', 'Remaining (bytes)', 'Exhausted', 'Description']
        rows = [[group['mode'], group['bytes'], group['used'], group['remaining'],
                 'Yes' if group['exhausted'] else 'No',
                 _value(group.get('description', ''), 'description', private)]]
    else:
        fields = [field for field in ('rate', 'burst', 'over', 'packets', 'bytes', 'description') if field in group]
        headers = [_label(field) for field in fields]
        rows = [[_value(group[field], field, private) for field in fields]]

    if detail:
        detailed_output(rows, headers)
    else:
        print(tabulate(rows, headers=headers, disable_numparse=True))
        print()


def _show_group(group, private, detail):
    """Print a normalized group's metadata and members using its key order.

    Configured match fields label columns; absent configuration falls back to
    installed datatypes. Tracking columns reflect available native statements.
    Unsupported entries are omitted with a warning, never presented as complete.
    """
    family = next((family for family in ('ipv4', 'ipv6', 'inet') if group['name'].startswith(family + '_')), None)
    family_title = family.replace('ip', 'IP') if family else None
    title = ' '.join(part for part in (family_title, group['group-kind'], group['group-name']) if part)
    _section_heading(title)

    metadata = ['description', 'flags', 'timeout', 'gc-interval', 'size']
    if group.get('configured-limit'):
        metadata.append('configured-limit')
    fields = [field for field in metadata if field in group]
    if fields:
        values = []
        for field in fields:
            value = _value(group[field], field, private)
            if field in ('timeout', 'gc-interval'):
                value += 's'
            values.append(value)
        metadata_headers = [_label(field) for field in fields]
        if detail:
            detailed_output([values], metadata_headers)
        else:
            print(tabulate([values], headers=metadata_headers, disable_numparse=True))
            print()

    datatypes = group['key-datatypes']
    # Concatenation positions must stay aligned with native element keys; sorting
    # the headers independently would attribute values to the wrong fields.
    match_fields = group.get('match-fields')
    if match_fields is None:
        match_fields = [f'key {index + 1} ({datatype})' for index, datatype in enumerate(datatypes)]
        print('Configured match fields unavailable; columns follow installed key order.\n')
    headers = ['Entry'] + [_label(field) for field in match_fields]
    if 'result-datatypes' in group:
        headers.append('Result')
    if group.get('counter'):
        headers.extend(['Packets', 'Bytes'])
    if group.get('last-used'):
        headers.append('Last used')
    if 'timeout' in group or 'timeout' in group.get('flags', []):
        headers.append('Expires')
    headers.append('Description')

    rows = []
    for entry in group.get('entries', []):
        if 'unsupported' in entry:
            continue
        row = [entry.get('name', MISSING)]
        values = ['*'] * len(datatypes) if entry.get('default') else entry['key']
        for index, value in enumerate(values):
            row.append(_value(value, datatypes[index], private))
        if 'result-datatypes' in group:
            row.append(_group_result(entry['result'], private))
        if group.get('counter'):
            counter = entry.get('counter', {})
            row.extend([counter.get('packets', MISSING), counter.get('bytes', MISSING)])
        if group.get('last-used'):
            row.append(_last_used(entry))
        if 'Expires' in headers:
            row.append(f"{entry['expires']:g}s" if 'expires' in entry else MISSING)
        row.append(_value(entry.get('description', ''), 'description', private))
        rows.append(row)

    alignment = ['right' if header in ('Packets', 'Bytes') else 'left' for header in headers]
    if rows and detail:
        detailed_output(rows, headers)
    elif rows:
        print(tabulate(rows, headers=headers, disable_numparse=True, colalign=alignment))
    else:
        print('No elements listed.')

    if group.get('unsupported') or any('unsupported' in entry for entry in group.get('entries', [])):
        print('Warning: unsupported group data is present; this display is incomplete.')
    print()


def _base_chain_view(chain, *, numbered):
    """Separate direct inet rules from generated state policies and dispatch."""
    rules = [rule for rule in chain.get('rules', [])
             if (str(rule.get('number', '')).isdigit()
                 or str(rule.get('number', '')).startswith('source-validation-')) == numbered]
    return dict(chain, rules=rules)


def _chains(table, family, hook, stage, named, chain_name):
    """Select nVyR firewall chains, excluding the NAT chains in the shared table."""
    for name, chain in table.get('chains', {}).items():
        if name in NFT_FILTER_HOOKS:
            if family is None and hook is None and not named and name != 'ingress' and NFT_FILTER_HOOKS[name][1] == 'filter':
                yield f'State policy ({name})', _base_chain_view(chain, numbered=False)
            candidate_hook, candidate_stage = NFT_FILTER_HOOKS[name]
            if (family in (None, 'inet') and not named
                    and hook in (None, candidate_hook) and stage in (None, candidate_stage)):
                view = _base_chain_view(chain, numbered=True)
                if view['rules'] or family == 'inet':
                    yield f'inet {candidate_hook} {candidate_stage}', view
            continue

        for candidate_family in ('ipv4', 'ipv6', 'inet'):
            if family and candidate_family != family:
                continue
            family_title = candidate_family.replace('ip', 'IP')
            prefix = candidate_family + '_name_'
            if name.startswith(prefix):
                if hook is None and (chain_name is None or name == prefix + chain_name):
                    yield f'{family_title} name {name[len(prefix):]}', chain
            elif not named:
                for entrypoint, (candidate_hook, candidate_stage) in NFT_FILTER_HOOKS.items():
                    if hook is not None and hook != candidate_hook:
                        continue
                    if stage is not None and stage != candidate_stage:
                        continue
                    if name == f'{candidate_family}_{entrypoint}':
                        yield f'{family_title} {candidate_hook} {candidate_stage}', chain


def _bytes(value):
    """Use binary units for display; normalized/API values remain exact byte counts."""
    for unit, divisor in (('GiB', 1024 ** 3), ('MiB', 1024 ** 2), ('KiB', 1024)):
        if value >= divisor:
            return f'{value / divisor:.3f}'.rstrip('0').rstrip('.') + ' ' + unit
    return f'{value} B'


def _installed_object(table, category, name):
    """Missing dependencies are an incomplete listing, not zero usage or no keys."""
    value = table.get(category, {}).get(name)
    if value is None or value.get('unsupported'):
        raise OperationalError(f'Cannot read installed firewall object {name!r}.')
    return value


def _limit_records(table, chain, rule):
    """Resolve private sets and shared groups using installed rule expressions."""
    for kind in ('limit', 'connection-limit'):
        if kind not in rule:
            continue
        options = rule[kind]
        group = options.get('group')
        runtime = rule.get('runtime-limits', {}).get(kind)
        state = None
        if runtime is not None:
            options = runtime
            state = _installed_object(table, 'sets', runtime['set'])
        elif group is not None:
            family = 'inet' if chain['name'] in NFT_FILTER_HOOKS else chain['name'].split('_', 1)[0]
            options = _installed_object(table, 'limits', nft_limit_group_name(family, group))

        record = {'rule': rule['number'], 'kind': kind, 'parameters': options}
        if group is not None:
            record['group'] = group
        if state is not None:
            entries = state.get('entries', [])
            fields = options['per']
            if any('unsupported' in entry or len(entry['key']) != len(fields) for entry in entries):
                raise OperationalError('Cannot interpret installed limit keys.')
            record.update({'fields': fields, 'entries': entries, 'active-keys': len(entries),
                           'capacity': state.get('size')})
            if 'timeout' in state.get('flags', []) or 'timeout' in state:
                record['timeout'] = state.get('timeout')
        yield record


def _show_limit(record, title, private):
    """Show parameters separately from observed keys; never infer bucket occupancy."""
    label = 'connection limit' if record['kind'] == 'connection-limit' else 'rate limit'
    _section_heading(f'{title} — Rule {record["rule"]} {label}')
    parameters = record['parameters']
    summary = {}
    if 'group' in record:
        summary['Group (shared)'] = record['group']
    if record['kind'] == 'connection-limit':
        summary['Over connections'] = parameters['over']
    else:
        summary['Mode'] = 'over' if parameters.get('over') else 'until'
        unit, rate = next(iter(parameters['rate'].items()))
        summary['Rate'] = rate + ' ' + unit
        burst = parameters.get('burst', {})
        summary['Burst'] = f'{burst[unit]} {unit}' if unit in burst else MISSING
    if 'entries' in record:
        summary['Active keys'] = record['active-keys']
        summary['Capacity'] = record['capacity'] if record['capacity'] is not None else MISSING
    print(tabulate([summary], headers='keys', disable_numparse=True))
    print()

    if 'entries' not in record:
        print('Shared allowance across matching traffic; no per-key entries.\n')
        return
    fields = record['fields']
    headers = []
    for field in fields:
        label = _label(field)
        prefix = parameters.get(field.replace('-address', '-prefix-length'))
        if field in ('source-address', 'destination-address') and prefix is not None:
            label += f' (/{prefix})'
        headers.append(label)
    if 'timeout' in record:
        headers.append('Expires')

    rows = []
    for entry in record['entries']:
        row = [_value(value, field, private) for field, value in zip(fields, entry['key'], strict=True)]
        if 'timeout' in record:
            row.append(f'{entry["expires"]:g}s' if 'expires' in entry else MISSING)
        rows.append(row)
    if rows:
        print(tabulate(rows, headers=headers, disable_numparse=True))
    else:
        print('No active keys recorded.')
    print()


@opmode.command
def runtime(kind: str, family: str | None = None, hook: str | None = None, stage: str | None = None,
            named: bool = False, chain_name: str | None = None, rule: str | None = None,
            strip_private: str | None = None, raw: bool = False):
    """Inspect installed limits or quotas without resetting any state."""
    if kind not in ('limit', 'quota'):
        raise OperationalError('Select limit or quota runtime state.')
    if rule is not None and named and chain_name is None:
        raise OperationalError('Specify a named chain before selecting a rule.')

    table = _load_table()
    sections = []
    for title, chain in _chains(table, family, hook, stage, named, chain_name):
        rules = chain.get('rules', [])
        if rule is not None:
            rules = [entry for entry in rules if entry.get('number') == rule]
            if not rules:
                raise OperationalError(f'Rule {rule} is not installed in {title}.')

        records = []
        incomplete = any(entry.get('unsupported') for entry in rules)
        for entry in rules:
            if kind == 'limit':
                records.extend(_limit_records(table, chain, entry))
            elif 'quota' in entry:
                quota = entry['quota']
                group = quota.get('group')
                if group is not None:
                    quota = _installed_object(table, 'quotas', nft_quota_group_name(group))
                record = {'rule': entry['number'], 'mode': quota['mode'],
                          'bytes': quota['bytes'], 'used': quota['used'],
                          'remaining': max(0, quota['bytes'] - quota['used'])}
                if group is not None:
                    record['group'] = group
                records.append(record)
        sections.append({'chain': chain.get('name'), 'title': title, 'records': records,
                         'incomplete': incomplete})

    if not sections and (chain_name or rule):
        raise OperationalError('The requested firewall object is not installed.')
    if raw:
        return json.dumps(sections)
    if not sections:
        print('No firewall objects installed in this scope.')
    for section in sections:
        title = section['title']
        records = section['records']
        if kind == 'limit' and records:
            for record in records:
                _show_limit(record, title, strip_private)
        else:
            suffix = f' — Rule {rule} {kind}' if rule is not None else f' — {kind}s'
            _section_heading(title + suffix)
            if records:
                rows = []
                shared = any('group' in record for record in records)
                for record in records:
                    row = {'Rule': record['rule']}
                    if shared:
                        row['Group (shared)'] = record.get('group', MISSING)
                    row.update({'Mode': record['mode'], 'Quota': _bytes(record['bytes']),
                                'Used': _bytes(record['used']), 'Remaining': _bytes(record['remaining'])})
                    rows.append(row)
                print(tabulate(rows, headers='keys', disable_numparse=True))
                print()
            else:
                print(f'No {kind}s installed in this scope.\n')
        if section['incomplete']:
            print('Warning: unsupported expressions are present; this display is incomplete.\n')


@opmode.command
def show(family: str | None = None, hook: str | None = None, stage: str | None = None, named: bool = False,
         chain_name: str | None = None, rule: str | None = None,
         section: str | None = None, group_kind: str | None = None,
         group_name: str | None = None, strip_private: str | None = None, detail: bool = False,
         zone_name: str | None = None, failsafe: bool = False):
    """Show all firewall objects or a selected family, chain, rule, or group."""
    if rule is not None and named and chain_name is None:
        raise OperationalError('Specify a named chain before selecting a rule.')

    table = _load_table(failsafe=failsafe)
    if failsafe and not table:
        print('Fail-safe firewall is not active.')
        return
    shown = False

    if section == 'state-policy':
        for policy_hook, policy_stage in NFT_FILTER_HOOKS.values():
            if policy_hook == 'ingress' or policy_stage != 'filter' or (hook is not None and hook != policy_hook):
                continue
            chain = table.get('chains', {}).get(policy_hook)
            if chain is not None:
                _show_chain(f'State policy ({policy_hook})', _base_chain_view(chain, numbered=False), None, strip_private, detail)
                shown = True

    if section is None:
        for title, chain in _chains(table, family, hook, stage, named, chain_name):
            _show_chain(title, chain, rule, strip_private, detail)
            shown = True

    if section == 'zone' or (section is None and hook is None and not named):
        for mapping in table.get('maps', {}).values():
            if 'zone-hook' not in mapping or (family and not mapping['name'].startswith(family + '_')):
                continue
            if _show_zone_map(mapping, strip_private, detail, zone_name):
                shown = True

    if section == 'group' or (section is None and hook is None and not named):
        shown_timeouts = set()
        for category in ('sets', 'maps', 'counters', 'limits', 'quotas', 'ct timeouts'):
            for group in table.get(category, {}).values():
                if 'group-kind' not in group:
                    continue
                if family and not group['name'].startswith(family + '_'):
                    continue
                if group_kind and group['group-kind'] != group_kind:
                    continue
                if group_name and group['group-name'] != group_name:
                    continue
                if category == 'ct timeouts':
                    identity = nftables_timeouts.identity(group['name'])
                    if identity in shown_timeouts:
                        continue
                    shown_timeouts.add(identity)
                    objects = [item for item in table[category].values()
                               if nftables_timeouts.identity(item['name']) == identity]
                    _show_timeout_group(objects, strip_private, detail)
                elif category in ('counters', 'limits', 'quotas'):
                    _show_named_state(group, strip_private, detail)
                else:
                    _show_group(group, strip_private, detail)
                shown = True

    if section == 'flowtable' or (section is None and family is None and hook is None and not named):
        for name, flowtable in table.get('flowtables', {}).items():
            if not name.startswith('flowtable_'):
                continue
            name = name.removeprefix('flowtable_')
            if group_name and name != group_name:
                continue
            _section_heading(f'Flowtable {name}')
            fields = ['interface', 'hook', 'prio', 'flags']
            fields = [field for field in fields if field in flowtable]
            rows = [[_value(flowtable[field], field, strip_private) for field in fields]]
            headers = [_label(field) for field in fields]
            if detail:
                detailed_output(rows, headers)
            else:
                print(tabulate(rows, headers=headers, disable_numparse=True))
                print()
            shown = True

    if not shown:
        if chain_name or group_name or rule or zone_name:
            raise OperationalError('The requested firewall object is not installed.')
        print('No firewall objects installed in this scope.')


def _show_zone_map(mapping, private, detail, zone_name=None):
    """Read installed interface relationships and verdicts from native map elements."""
    family = mapping['name'].split('_')[0].replace('ip', 'IP')
    hook = mapping['zone-hook']
    entries = mapping.get('entries', [])
    if zone_name is not None:
        entries = [entry for entry in entries if entry.get('from-zone') == zone_name]
        if not entries:
            return False

    title = f'{family} zone {hook}'
    if zone_name is not None:
        title += f' (from {zone_name})'
    _section_heading(title)
    if hook == 'forward':
        headers = ['Inbound interface', 'Outbound interface', 'Zones', 'Action']
    else:
        headers = ['Inbound interface' if hook == 'input' else 'Outbound interface', 'Zone', 'Action']
    headers.extend(['Packets', 'Bytes'])

    rows = []
    for entry in entries:
        if 'unsupported' in entry:
            raise OperationalError('Cannot interpret an installed zone dispatch element.')
        verdict = entry['result']
        action = _action(verdict)
        counter = entry.get('counter', {})
        rows.append([*entry['key'], _value(entry.get('comment', ''), 'zone', private), action,
                     counter.get('packets', MISSING), counter.get('bytes', MISSING)])

    if detail:
        detailed_output(rows, headers)
    else:
        alignment = ['right' if header in ('Packets', 'Bytes') else 'left' for header in headers]
        print(tabulate(rows, headers=headers, disable_numparse=True, colalign=alignment))
        print()
    return True


def _reset_object(kind, name):
    """Reset only an explicitly named nVyR object, never the whole ruleset."""
    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,62}', name) is None:
        raise OperationalError(f'Invalid {kind} name.')

    native = nft_counter_group_name(name) if kind == 'counter' else nft_quota_group_name(name)
    status, output = rc_cmd(['nft', 'reset', kind, 'inet', 'nvyr_filter', native])
    if status:
        raise OperationalError(f'Cannot reset {kind} {name!r}: {output.strip() or "nftables reset failed."}')

    print(f'{kind.capitalize()} {name} reset.')


@opmode.command
def clear_counter(name: str):
    """Reset one named counter without changing configuration."""
    _reset_object('counter', name)


@opmode.command
def clear_quota(name: str):
    """Restore one named quota's full allowance without changing configuration."""
    _reset_object('quota', name)


@opmode.command
def clear_group(line: str):
    """Clear learned state through configd, coordinated with firewall commits."""
    try:
        client = Client('/run/nvyr/configd.sock')
        try:
            result = client.request('clear-firewall-group', text=line)
        finally:
            client.close()
    except (OSError, EOFError) as error:
        raise OperationalError(f'Cannot clear firewall group: {error}') from None

    print(result['text'], end='')


if __name__ == '__main__':
    opmode.run()
