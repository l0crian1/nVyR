"""Load one nftables file as a single kernel transaction."""

import os
import json
import re
from pathlib import Path
import subprocess
import tempfile

from nvyr.errors import RecoveryError, ValidationError, RouterError
from nvyr.storage import sync_directory
from nvyr.helpers.process import cmd, rc_cmd, CommandError
from nvyr.helpers.template import write
from nvyr.helpers.nftables_formatters import (
    NFT_KEYMAP, NFT_SINGLETON_REFERENCES, NFT_PORT_PROTOCOLS, NFT_NAT_PORT_PROTOCOLS, nft_present_fields, nft_group_fields,
    nft_group_protocols,
)


def verify_hook_fields(fields, hook, path):
    """Check key availability for explicit, inherited and dynamically extracted fields."""
    unsupported = sorted(field for field in fields if field in NFT_KEYMAP and hook not in NFT_KEYMAP[field].hooks)
    # Shared objects must not introduce fields unavailable at their consuming hook.
    if unsupported:
        raise ValidationError(f"{' '.join(path)}: {', '.join(unsupported)} unavailable in {hook}")


def verify_ports(rule, path, *, translation=False, mapping=None, match_group=None):
    """Require a port-bearing protocol, with separate NAT translation restrictions."""
    # Group entries validate their own port keys once; check only extra rule matches here.
    rule_fields = match_fields(rule)
    fields = [key for key in ('source-port', 'destination-port') if key in rule_fields]

    # Port translation also interprets transport headers.
    if translation:
        fields.append('translation port or port-mapping')

    # Without transport matches or translation there is no protocol requirement.
    if not fields:
        return

    family = path[1] if path[0] == 'firewall' else 'ipv4'
    protocols = match_protocols(rule, mapping, match_group, family=family)
    has_protocol = bool(rule.get('protocol')) or any(
        'protocol' in (definition or {}).get('match', {}) for definition in (mapping, match_group))
    # Translation retains its supported protocols; matching accepts all port transports.
    allowed = NFT_NAT_PORT_PROTOCOLS if translation else NFT_PORT_PROTOCOLS
    if not has_protocol or not protocols <= allowed:
        choices = ', '.join(sorted(allowed))
        raise ValidationError(f"{' '.join(path)}: {', '.join(fields)} requires an explicit port protocol ({choices})")


def match_fields(rule, mapping=None, match_group=None, excluded_group=None):
    """Collect field names without constructing a second configuration tree."""
    explicit = (set(rule) - {'not'}) | set(rule.get('not', {}))
    explicit.discard('connection')
    explicit.update(nft_present_fields(rule))
    explicit.update(nft_present_fields(rule, negative=True))
    singleton_fields = {field for reference, (_, field) in NFT_SINGLETON_REFERENCES.items() if reference in explicit}
    fields = explicit | singleton_fields
    if 'icmp-group' in explicit:
        fields.add('icmp-type')
    for definition in (mapping, match_group, excluded_group):
        fields.update(nft_group_fields(definition or {}))
    return fields


def match_protocols(rule, mapping=None, match_group=None, *, family='ipv4'):
    """Read the sole protocol source after duplicate-field verification."""
    for definition in (mapping, match_group):
        if definition and 'protocol' in definition.get('match', {}):
            if 'default-result' in definition:
                # A catch-all admits unlisted protocols too, subject only to the
                # generated header guard. None denotes an unconstrained protocol.
                return nft_group_protocols(family, nft_group_fields(definition), definition.get('result-type')) or {None}
            return {entry.get('protocol') for entry in definition.get('entry', {}).values()}

    return set(rule.get('protocol', ()))


def verify_icmp(rule, path, family, mapping=None, match_group=None, excluded_group=None):
    """Check ICMP fields across explicit matches and both referenced groups."""
    inherited_fields = match_fields({}, mapping, match_group, excluded_group)
    fields = match_fields(rule) | inherited_fields
    # Rules without ICMP matches need no ICMP cross-field checks.
    if not fields & {'icmp-type', 'icmp-code'}:
        return

    name = ' '.join(path)
    counts = {}
    for field in ('icmp-type', 'icmp-code'):
        counts[field] = sum(len(part.get(field, ())) for part in (rule, rule.get('not', {})))
        counts[field] += sum(field in (definition or {}).get('match', {})
                             for definition in (mapping, match_group, excluded_group))
    type_count, code_count = counts['icmp-type'], counts['icmp-code']

    # Pairing type and code is unambiguous only with one value of each.
    if type_count and code_count and (type_count != 1 or code_count != 1):
        raise ValidationError(f'{name}: configuring both icmp-type and icmp-code requires exactly one of each')

    # ICMP headers cannot also be interpreted as port-bearing transport headers.
    conflicts = fields & {'source-port', 'destination-port', 'tcp-mss', 'tcp-flags'}
    if conflicts:
        raise ValidationError(f'{name}: ICMP matching cannot be combined with ' + ', '.join(sorted(conflicts)))

    # ICMP matching requires an explicit, family-specific protocol constraint.
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    has_protocol = bool(rule.get('protocol')) or 'protocol' in match_fields({}, mapping, match_group)
    # A negated ICMP group supplies a positive header guard, not its entries' protocols.
    has_protocol = has_protocol or bool(set((excluded_group or {}).get('match', {})) & {'icmp-type', 'icmp-code'})
    if not has_protocol or match_protocols(rule, mapping, match_group, family=family) - {protocol}:
        raise ValidationError(f'{name}: ICMP matching requires protocol {protocol}')


def verify_map_reference(rule, path, maps, result_types):
    """A map supplies its key matches and result; other rule matches remain independent."""
    name = ' '.join(path)
    selected = maps.get(rule['map'])
    # References must resolve to a configured map in the caller's address family.
    if selected is None:
        raise ValidationError(f"{name}: map {rule['map']!r} is not configured in this address family")

    # The map result must be usable by this firewall or NAT consumer.
    if selected.get('result-type') not in result_types:
        raise ValidationError(f'{name}: map result-type must be ' + ' or '.join(sorted(result_types)))

    # The same field cannot be matched both by the rule and by the map key.
    conflicts = nft_present_fields(rule) & set(nft_group_fields(selected))
    # The map supplies the result, so a consuming rule cannot specify another one.
    conflicts.update(set(rule) & {'action', 'jump-target', 'offload-target', 'translation', 'exclude'})
    if conflicts:
        raise ValidationError(f'{name}: map cannot be combined with ' + ', '.join(sorted(conflicts)))
    return selected


def verify_match_group_reference(rule, path, match_groups, mapping=None):
    # Rules without a match-group need no additional reference checks.
    if 'match-group' not in rule:
        return None

    name = ' '.join(path)
    selected = match_groups.get(rule['match-group'])
    # Match-group references must resolve within the rule's address family.
    if selected is None:
        raise ValidationError(f"{name}: match-group {rule['match-group']!r} is not configured in this address family")

    fields = set(nft_group_fields(selected))
    explicit = fields & nft_present_fields(rule)
    inherited = fields & set(nft_group_fields(mapping or {}))
    # Each packet field must come from exactly one source: rule, map, or match-group.
    if explicit or inherited:
        conflicts = []
        if explicit:
            conflicts.append('rule: ' + ', '.join(sorted(explicit)))
        if inherited:
            conflicts.append('map: ' + ', '.join(sorted(inherited)))
        raise ValidationError(f"{name}: match-group duplicates match fields from " + '; '.join(conflicts))

    return selected


def verify_exclusions(rule, path, family, groups, match_groups):
    """Validate negative references against their own matching polarity."""
    excluded = rule.get('not', {})
    # No negative references exist when the exclusion branch is absent or empty.
    if not excluded:
        return None

    match_group = verify_match_group_reference(excluded, path, match_groups)
    verify_singleton_references(excluded, path, family, groups, match_group=match_group)
    return match_group


def verify_singleton_references(rule, path, family, groups, mapping=None, match_group=None):
    """Resolve typed references and reject duplicate packet fields from any source."""
    # Resolve inherited fields only when this rule actually references a singleton group.
    if NFT_SINGLETON_REFERENCES.keys().isdisjoint(rule):
        return

    name = ' '.join(path)
    inherited = match_fields({}, mapping, match_group)
    for reference, (kind, field) in NFT_SINGLETON_REFERENCES.items():
        # Only configured references need existence and conflict checks.
        if reference not in rule:
            continue

        definitions = groups.get(kind, {})
        if kind in ('address-group', 'domain-group'):
            definitions = definitions.get(family, {})
        # Address references must resolve in this family; other types are shared.
        if rule[reference] not in definitions:
            raise ValidationError(f"{name}: {reference} {rule[reference]!r} is not configured for {family}")

        # Different group types must not claim the same packet field.
        if field in inherited:
            raise ValidationError(f'{name}: {reference} duplicates {field} from another group or map')

        # A singleton group cannot duplicate an explicit rule match field.
        if field in rule:
            raise ValidationError(f'{name}: {reference} duplicates {field} from the rule, map or match-group')
        inherited.add(field)


def verify_rule_statements(rule, path, groups):
    """Shared firewall/NAT counter references and kernel logging options."""
    # Rules with neither statement have no counter references or logging flags to check.
    if 'counter' not in rule and 'log' not in rule:
        return

    name = ' '.join(path)
    counter = rule.get('counter', {})
    # Named counters must exist even when no other rule refers to them yet.
    if 'group' in counter and counter['group'] not in groups.get('counter-group', {}):
        raise ValidationError(f"{name}: counter group {counter['group']!r} is not configured")

    logging = rule.get('log', {})
    # A collector must be configured before a rule can send packets to it.
    if 'group' in logging and logging['group'] not in groups.get('log-group', {}):
        raise ValidationError(f"{name}: log group {logging['group']!r} is not configured")
    # NFLOG transfers packets; kernel text formatting options do not apply.
    if 'group' in logging and ('level' in logging or 'flags' in logging):
        raise ValidationError(f'{name}: log group cannot be combined with level or flags')

    flags = logging.get('flags', '').split(',')
    # All already includes every individual logging detail.
    if 'all' in flags and len(flags) != 1:
        raise ValidationError(f'{name}: log flags all cannot be combined with other flags')


class Manager:
    def icmp_groups(self):
        return self._groups('set', 'icmp_group')

    def maps(self):
        return self._groups('map', 'map')

    def match_groups(self):
        return self._groups('set', 'match_group')

    def singleton_groups(self):
        """Discover only the reserved singleton namespaces for restart cleanup."""
        result = json.loads(cmd(['nft', '--json', 'list', 'sets', 'inet']))
        names = []
        for item in result['nftables']:
            group = item.get('set', {})
            if group.get('family') != 'inet' or group.get('table') != 'nvyr_filter':
                continue
            if re.fullmatch(r'(?:ipv[46]_(?:address|domain)|interface|mac|port)_group_[A-Za-z_][A-Za-z0-9_-]{0,62}', group['name']):
                names.append(group['name'])
        return names

    def rule_limits(self):
        """Find private per-rule limit sets after a restart or interrupted apply."""
        result = json.loads(cmd(['nft', '--json', 'list', 'sets', 'inet']))
        names = []
        for item in result['nftables']:
            group = item.get('set', {})
            if group.get('family') != 'inet' or group.get('table') != 'nvyr_filter':
                continue
            if re.fullmatch(r'rule_(?:limit|connection_limit)_(?:ipv[46]|inet)_[A-Za-z0-9_-]+_[0-9]+', group['name']):
                names.append(group['name'])
        return names

    def named_state(self):
        """Discover shared counters, quotas, limits and timeout policies for recovery."""
        objects = []
        patterns = {
            'counter': r'counter_group_[A-Za-z_][A-Za-z0-9_-]{0,62}',
            'quota': r'quota_group_[A-Za-z_][A-Za-z0-9_-]{0,62}',
            'limit': r'(?:ipv[46]|inet)_limit_group_[A-Za-z_][A-Za-z0-9_-]{0,62}',
            'set': r'(?:ipv[46]|inet)_limit_group_[A-Za-z_][A-Za-z0-9_-]{0,62}',
        }
        for kind, pattern in patterns.items():
            # Inventory listings omit rules and potentially large learned-element lists.
            result = json.loads(cmd(['nft', '--json', 'list', kind + 's', 'inet']))
            for record in result['nftables']:
                data = record.get(kind, {})
                if (data.get('family') == 'inet' and data.get('table') == 'nvyr_filter'
                        and re.fullmatch(pattern, data['name'])):
                    objects.append((kind, data['name']))

        # nft has no plural ct-timeout inventory command. Recovery reads the table
        # with large set elements omitted, retaining only owned timeout objects.
        if self.table_exists('nvyr_filter'):
            from nvyr.helpers.nftables_timeouts import identity

            result = json.loads(cmd(['nft', '--json', '--terse', 'list', 'table', 'inet', 'nvyr_filter']))
            for record in result['nftables']:
                data = record.get('ct timeout', {})
                if data and identity(data['name']):
                    objects.append(('ct timeout', data['name']))
        return objects

    def _groups(self, kind, prefix):
        """Discover owned groups left by an interrupted transaction."""
        result = json.loads(cmd(['nft', '--json', 'list', kind + 's', 'inet']))
        names = []
        for item in result['nftables']:
            group = item.get(kind, {})
            if group.get('family') != 'inet' or group.get('table') != 'nvyr_filter':
                continue
            match = re.fullmatch(rf'(ipv[46]|inet)_{prefix}_([A-Za-z_][A-Za-z0-9_-]{{0,62}})', group['name'])
            if match:
                names.append(match.groups())
        return names

    def flowtables(self):
        """Discover owned flowtables left by an interrupted firewall apply."""
        result = json.loads(cmd(['nft', '--json', 'list', 'flowtables', 'inet']))
        names = []

        for item in result['nftables']:
            flowtable = item.get('flowtable', {})
            if flowtable.get('family') != 'inet' or flowtable.get('table') != 'nvyr_filter':
                continue

            match = re.fullmatch(r'flowtable_([A-Za-z_][A-Za-z0-9_-]{0,62})', flowtable['name'])
            if match:
                names.append(match.group(1))

        return names

    def named_chains(self):
        """Discover owned dynamic chains for reconciliation after interrupted apply."""
        result = json.loads(cmd(['nft', '--json', 'list', 'chains', 'inet']))
        names = []

        for item in result['nftables']:
            chain = item.get('chain', {})
            if chain.get('family') != 'inet' or chain.get('table') != 'nvyr_filter':
                continue

            # Only this reserved, schema-generated namespace belongs to firewall.
            match = re.fullmatch(r'(ipv[46]|inet)_name_([A-Za-z_][A-Za-z0-9_-]{0,62})', chain['name'])
            if match:
                names.append(match.groups())

        return names

    def table_exists(self, name):
        """Inventory tables without treating a failed nft query as an absent table."""
        result = json.loads(cmd(['nft', '--json', 'list', 'tables']))
        return any(item.get('table', {}).get('family') == 'inet'
                   and item['table'].get('name') == name for item in result['nftables'])

    def apply(self, configuration, state_directory, *, owner='firewall', accounting=None, check_only=False):
        if not isinstance(owner, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', owner):
            raise ValueError('Invalid nftables owner name')

        directory = Path(state_directory)

        # Keep the last successfully loaded file, never a rejected candidate.
        with tempfile.TemporaryDirectory(prefix='.nft-', dir=directory) as work:
            candidate = Path(work) / f'{owner}.nft'
            write(candidate, configuration)
            status, output = rc_cmd(['nft', '--check', '--file', str(candidate)])
            if status:
                raise ValidationError(output.strip() or 'nftables rejected the proposed configuration')

            if check_only:
                return

            accounting_path = Path('/proc/sys/net/netfilter/nf_conntrack_acct')
            previous_accounting = None
            try:
                if accounting is not None:
                    if accounting and not accounting_path.exists():
                        cmd(['modprobe', 'nf_conntrack'])
                    if accounting or accounting_path.exists():
                        previous_accounting = accounting_path.read_text().strip()
                        accounting_path.write_text('1' if accounting else '0')
            except OSError as error:
                raise RouterError(f'Could not configure connection accounting: {error}') from error

            try:
                status, output = rc_cmd(['nft', '--file', str(candidate)])
                if status:
                    raise RouterError(output.strip() or 'Could not apply the nftables configuration')
            except Exception as error:
                if previous_accounting is not None:
                    try:
                        accounting_path.write_text(previous_accounting)
                    except OSError as restore_error:
                        raise RecoveryError('Could not restore connection accounting after nftables failed; restart configd to recover.') from restore_error
                if isinstance(error, CommandError) and isinstance(error.__cause__, subprocess.TimeoutExpired):
                    raise RecoveryError('nftables load timed out; its outcome is uncertain. Restart configd to restore the journaled configuration.') from error

                raise

            try:
                os.replace(candidate, directory / f'{owner}.nft')
                sync_directory(directory)
            except OSError as error:
                raise RecoveryError('nftables loaded but its configuration file could not be published; restart configd to recover.') from error


manager = Manager()
