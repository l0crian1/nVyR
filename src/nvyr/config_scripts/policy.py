"""Reusable routing policies applied through the shared FRR reload pipeline."""

import ipaddress
from collections.abc import Mapping

from nvyr.errors import ValidationError
from nvyr.helpers import frr_policy, frr_reload
from nvyr.helpers.template import render
from nvyr.tree import lookup


def get_config(context):
    return lookup(context.effective, ('policy',), {})


def _verify_bgp_lists(configuration):
    definitions = [('as-path-list', 'expanded', lookup(configuration, ('as-path-list',), {}))]
    for kind in ('community-list', 'large-community-list'):
        modes = lookup(configuration, (kind,), {})
        duplicates = set(lookup(modes, ('standard',), {})) & set(lookup(modes, ('expanded',), {}))
        # FRR has one name namespace for both representations of a community list.
        if duplicates:
            raise ValidationError(f'policy {kind}: names cannot be both standard and expanded: {", ".join(sorted(duplicates))}')
        definitions.extend((kind, mode, lists) for mode, lists in modes.items())

    for kind, mode, lists in definitions:
        for name, values in lists.items():
            path = f'policy {kind} {name}'
            # Empty native lists cannot be created; an explicit deny expresses deny-all.
            if not lookup(values, ('rule',), None):
                raise ValidationError(f'{path}: at least one rule is required')
            for sequence, rule in values['rule'].items():
                entry = f'{path} rule {sequence}'
                # A list entry must have an explicit filtering verdict.
                if 'action' not in rule:
                    raise ValidationError(f'{entry}: action permit or deny is required')
                field = 'regex' if mode == 'expanded' else 'community'
                # Missing operands must never become broad permit statements.
                if not lookup(rule, (field,), None):
                    raise ValidationError(f'{entry}: {field} is required')


def _verify_reference(configuration, kind, name, path):
    definitions = lookup(configuration, (kind,), {})
    if kind in ('community-list', 'large-community-list'):
        definitions = set(lookup(definitions, ('standard',), {})) | set(lookup(definitions, ('expanded',), {}))
    # Dependency guards protect deletions; missing references must also fail before apply.
    if name not in definitions:
        raise ValidationError(f'{path}: {kind} {name!r} is not configured')


def _verify_flow(configuration, name, sequence, rule, path):
    flow = lookup(rule, ('on-match',), {})
    # An explicitly configured continuation needs exactly one behavior.
    if 'on-match' in rule and len(flow) != 1:
        raise ValidationError(f'{path}: on-match requires exactly one of next or goto')
    # FRR only permits forward jumps, preventing route-map loops.
    if 'goto' in flow and int(flow['goto']) <= sequence:
        raise ValidationError(f'{path}: on-match goto must move forward')
    # Deny entries terminate immediately, so calls and continuation would be ineffective.
    if rule['action'] == 'deny' and ('call' in rule or flow):
        raise ValidationError(f'{path}: call and on-match require action permit')
    if 'call' in rule:
        _verify_reference(configuration, 'route-map', rule['call'], path)


def _verify_call_graph(configuration):
    graph = {name: {rule['call'] for rule in values['rule'].values() if 'call' in rule}
             for name, values in lookup(configuration, ('route-map',), {}).items()}
    completed = set()
    visiting = []

    def visit(name):
        # Recursive calls cannot finish normally and FRR would eventually deny at its depth limit.
        if name in visiting:
            raise ValidationError('Route-map call cycle: ' + ' -> '.join([*visiting, name]))
        if name in completed:
            return
        visiting.append(name)
        for target in graph[name]:
            visit(target)
        visiting.pop()
        completed.add(name)

    for name in graph:
        visit(name)


def _verify_filter(kind, rule, path):
    # Every native entry needs an explicit verdict; an incomplete rule must not permit routes.
    if 'action' not in rule:
        raise ValidationError(f'{path}: action permit or deny is required')

    if kind == 'prefix-list':
        # Prefix-list length comparisons have no meaning without a network prefix.
        if 'prefix' not in rule:
            raise ValidationError(f'{path}: prefix is required')

        prefix = ipaddress.ip_network(rule['prefix'])
        ge = int(rule['ge']) if 'ge' in rule else None
        le = int(rule['le']) if 'le' in rule else None

        # A matching prefix cannot be shorter than the configured network.
        if ge is not None and ge < prefix.prefixlen:
            raise ValidationError(f'{path}: ge cannot be less than prefix length {prefix.prefixlen}')

        # The maximum length must also include at least the configured network.
        if le is not None and le < prefix.prefixlen:
            raise ValidationError(f'{path}: le cannot be less than prefix length {prefix.prefixlen}')

        # A lower bound above the upper bound cannot match any route.
        if ge is not None and le is not None and ge > le:
            raise ValidationError(f'{path}: ge cannot exceed le')

        return

    modes = sum(key in rule for key in ('prefix', 'address', 'any'))
    # ACL forms map to mutually exclusive native choices.
    if modes != 1:
        raise ValidationError(f'{path}: choose prefix, address with wildcard-mask, or any')

    # A wildcard comparison needs both operands; a mask alone is incomplete.
    if ('address' in rule) != ('wildcard-mask' in rule):
        raise ValidationError(f'{path}: address and wildcard-mask must be configured together')

    # Exactness describes a prefix length, not a wildcard or any-address comparison.
    if 'exact-match' in rule and 'prefix' not in rule:
        raise ValidationError(f'{path}: exact-match requires prefix')


def _verify_nonempty_nodes(values, path):
    # An explicitly started match must not silently become a match-all rule;
    # an explicitly started setter must not silently become a no-op.
    if not values:
        raise ValidationError(f'{path}: at least one setting is required')

    for key, value in values.items():
        if key in ('community-list', 'large-community-list'):
            continue
        if isinstance(value, Mapping) and key not in ('peer-address', 'unchanged', 'prefer-global', 'all', 'any'):
            _verify_nonempty_nodes(value, f'{path} {key}')


def _verify_route_map(configuration, rule, path):
    # A route-map entry must explicitly choose whether matched routes are permitted.
    if 'action' not in rule:
        raise ValidationError(f'{path}: action permit or deny is required')

    for key in ('match', 'set'):
        if key in rule:
            _verify_nonempty_nodes(rule[key], f'{path} {key}')

    matches = lookup(rule, ('match',), {})
    if 'as-path-list' in matches:
        _verify_reference(configuration, 'as-path-list', matches['as-path-list'], path)
    for kind in ('community-list', 'large-community-list'):
        if kind not in matches:
            continue
        # FRR has one match slot for each community family, not several independent lists.
        if len(matches[kind]) != 1:
            raise ValidationError(f'{path}: match {kind} requires exactly one list')
        for name, flags in matches[kind].items():
            _verify_reference(configuration, kind, name, path)
            # Any-member and exact-set matching express incompatible modes.
            if 'any' in flags and 'exact-match' in flags:
                raise ValidationError(f'{path}: any and exact-match are mutually exclusive')
    for family in ('ipv4', 'ipv6'):
        family_matches = lookup(matches, (family,), {})
        for values in (family_matches, lookup(family_matches, ('next-hop',), {})):
            for kind in ('access-list', 'prefix-list'):
                name = lookup(values, (kind,), None)
                # Dependency registration protects deletion; verification also rejects missing providers.
                if name is not None and name not in lookup(configuration, (kind, family), {}):
                    raise ValidationError(f'{path}: {family} {kind} {name!r} is not configured')
        next_hop = lookup(family_matches, ('next-hop',), {})
        # Direct next-hop addresses and ACLs share FRR's native match slot.
        if 'address' in next_hop and 'access-list' in next_hop:
            raise ValidationError(f'{path}: next-hop address and access-list are mutually exclusive')

    settings = lookup(rule, ('set',), {})
    for kind in ('community', 'large-community'):
        values = lookup(settings, (kind,), ())
        # Additive only modifies how actual communities are installed.
        if values and all(value == 'additive' for value in values):
            raise ValidationError(f'{path}: set {kind} additive requires at least one community')
        # Clearing a community attribute cannot also add values to it.
        if 'none' in values and len(values) != 1:
            raise ValidationError(f'{path}: set {kind} none cannot be combined with other values')
        if kind + '-delete' in settings:
            _verify_reference(configuration, kind + '-list', settings[kind + '-delete'], path)
            # Clearing the entire attribute makes selective deletion redundant.
            if 'none' in values:
                raise ValidationError(f'{path}: set {kind} none cannot be combined with selective deletion')

    as_path = lookup(settings, ('as-path',), {})
    # Explicit prepending and repeating the leftmost AS share one native setter.
    if 'prepend' in as_path and 'prepend-last-as' in as_path:
        raise ValidationError(f'{path}: prepend and prepend-last-as are mutually exclusive')
    for mode in ('exclude', 'replace'):
        if mode not in as_path:
            continue
        selection = as_path[mode]
        selectors = ('as-number', 'as-path-list', 'all' if mode == 'exclude' else 'any')
        # Each native AS-path operation needs exactly one selection method.
        if sum(key in selection for key in selectors) != 1:
            raise ValidationError(f'{path}: as-path {mode} requires exactly one selection')
        if 'as-path-list' in selection:
            _verify_reference(configuration, 'as-path-list', selection['as-path-list'], path)

    for family in ('ipv4', 'ipv6'):
        next_hop = lookup(settings, (family, 'next-hop'), {})
        explicit = {'global', 'local'} if family == 'ipv6' else {'address'}
        modes = set(next_hop) - explicit
        # Global and link-local addresses may coexist; automatic modes exclude explicit values.
        if len(modes) > 1 or (modes and set(next_hop) & explicit):
            raise ValidationError(f'{path}: {family} next-hop modes are mutually exclusive')


def verify(configuration, context):
    _verify_bgp_lists(configuration)
    for kind in ('access-list', 'prefix-list'):
        for family, lists in lookup(configuration, (kind,), {}).items():
            for name, values in lists.items():
                # Native CLI cannot represent an empty policy; require an explicit deny rule instead.
                if not lookup(values, ('rule',), None):
                    raise ValidationError(f'policy {kind} {family} {name}: at least one rule is required')

                for sequence, rule in lookup(values, ('rule',), {}).items():
                    path = f'policy {kind} {family} {name} rule {sequence}'
                    _verify_filter(kind, rule, path)

    for name, values in lookup(configuration, ('route-map',), {}).items():
        # A named route-map needs a sequence to exist in FRR's native configuration.
        if not lookup(values, ('rule',), None):
            raise ValidationError(f'policy route-map {name}: at least one rule is required')

        for sequence, rule in lookup(values, ('rule',), {}).items():
            path = f'policy route-map {name} rule {sequence}'
            _verify_route_map(configuration, rule, path)
            _verify_flow(configuration, name, int(sequence), rule, path)

    _verify_call_graph(configuration)


def generate(configuration, context):
    text = render('frr/policy.conf.j2', {'configuration': configuration})
    return frr_policy.adapter.desired(text)


def apply(generated, context):
    frr_reload.manager.apply('policy', generated, context.state_directory,
                             adapter=frr_policy.adapter, daemons=('zebra', 'bgpd'),
                             recovery=context.recovery)
