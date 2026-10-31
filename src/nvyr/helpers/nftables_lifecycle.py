"""Select whole nftables objects, expanding changes through registered references."""

from collections import defaultdict, deque

from nvyr.helpers import nftables_helpers, nftables_timeouts
from nvyr.helpers import nftables_formatters as nft
from nvyr.helpers import nftables_zones as zones
from nvyr.helpers import nftables_source_validation as source_validation
from nvyr.tree import lookup


IP_FAMILIES = ('ipv4', 'ipv6')
FAMILIES = (*IP_FAMILIES, 'inet')
NAT_HOOKS = {'source': 'postrouting', 'destination': 'prerouting'}


def object_paths(configuration):
    """Index native objects by their owning configuration path, without copying data."""
    result = {}
    firewall = configuration.get('firewall', {})
    if nftables_helpers.configured(firewall):
        result['map', nftables_helpers.MAP_NAME] = nftables_helpers.PATH
        for name, (helper, _, _) in nftables_helpers.objects(firewall).items():
            result['ct helper', name] = (*nftables_helpers.PATH, helper)

    for family in FAMILIES:
        for kind in source_validation.interface_sets(firewall, family, configuration.get('vrf', {}).get('name', {})):
            name = source_validation.set_name(family, kind)
            result['set', name] = ('firewall', family, 'source-validation')

        for name in firewall.get(family, {}).get('name', {}):
            result['chain', nft.nft_named_chain(family, name)] = ('firewall', family, 'name', name)
        for entrypoint, (hook, stage) in nft.NFT_FILTER_HOOKS.items():
            if family == 'inet' and stage in firewall.get(family, {}).get(hook, {}):
                result['chain', entrypoint] = ('firewall', family, hook, stage)
            elif family in nft.nft_hook_families(firewall, entrypoint):
                result['chain', family + '_' + entrypoint] = ('firewall', family, hook, stage)

        for kind, native, formatter in [('map', 'map', nft.nft_map_name),
                                        ('match-group', 'set', nft.nft_match_group_name),
                                        ('icmp-group', 'set', nft.nft_icmp_group_name)]:
            for name in firewall.get('group', {}).get(kind, {}).get(family, {}):
                result[native, formatter(family, name)] = ('firewall', 'group', kind, family, name)

    for family, definitions in firewall.get('group', {}).get('timeout-group', {}).items():
        for name in definitions:
            for native in nftables_timeouts.native_names(family, name).values():
                result['ct timeout', native] = ('firewall', 'group', 'timeout-group', family, name)

    for name in firewall.get('group', {}).get('counter-group', {}):
        result['counter', nft.nft_counter_group_name(name)] = ('firewall', 'group', 'counter-group', name)
    for name in firewall.get('group', {}).get('quota-group', {}):
        result['quota', nft.nft_quota_group_name(name)] = ('firewall', 'group', 'quota-group', name)
    for family, definitions in firewall.get('group', {}).get('limit-group', {}).items():
        for name, options in definitions.items():
            kind = 'set' if 'per' in options else 'limit'
            result[kind, nft.nft_limit_group_name(family, name)] = ('firewall', 'group', 'limit-group', family, name)

    for kind, family, name, _ in nft.singleton_groups(firewall.get('group', {})):
        path = ('firewall', 'group', kind)
        if family:
            path += (family,)
        result['set', nft.nft_singleton_name(kind, family, name)] = (*path, name)

    for name in firewall.get('flowtable', {}):
        result['flowtable', nft.nft_flowtable_name(name)] = ('firewall', 'flowtable', name)
    for direction, hook in NAT_HOOKS.items():
        if direction in configuration.get('nat', {}):
            result['chain', 'ipv4_nat_' + hook] = ('nat', direction)

    # Private meter sets share the lifecycle of the complete firewall chain.
    for (kind, chain), path in list(result.items()):
        if kind != 'chain' or path[0] != 'firewall':
            continue
        if path[1] == 'inet' and path[2] != 'name':
            chain = 'inet_' + chain
        for number, rule in lookup(configuration, (*path, 'rule'), {}).items():
            if 'disable' in rule:
                continue
            for limit, suffix in nft.NFT_RULE_LIMIT_PATHS.items():
                if 'per' in lookup(rule, suffix, {}):
                    name = nft.nft_limit_name(chain, number, limit)
                    result['set', name] = (*path, 'rule', number, *suffix)
    return result


def entrypoints(configuration):
    """Synthetic dispatch chains depend on their targets and global state policy."""
    result = {}
    firewall = configuration.get('firewall', {})
    policies = firewall.get('global-options', {}).get('state-policy', {})
    for entrypoint in nft.nft_active_hooks(firewall):
        hook, stage = nft.NFT_FILTER_HOOKS[entrypoint]
        targets = tuple(('chain', family + '_' + entrypoint) for family in FAMILIES
                        if family in nft.nft_hook_families(firewall, entrypoint))
        policy_state = policies if stage == 'filter' and hook != 'ingress' else {}
        if stage == 'filter' and hook != 'ingress' and any(policy.get('action') == 'reject' for policy in policies.values()):
            policy_state = (policies, nft.nft_reject_response({}, firewall.get('global-options')))
        if entrypoint == 'ingress':
            policy_state = tuple(tuple(lookup(firewall, (family, hook, stage, 'interface'), [])) for family in FAMILIES)
        if entrypoint == 'forward':
            policy_state = (policy_state, firewall.get('global-options', {}).get('flowtable'))
        result['chain', entrypoint] = (targets, policy_state)
    for direction, hook in NAT_HOOKS.items():
        if direction in configuration.get('nat', {}):
            result['chain', 'nat_' + hook] = ((('chain', 'ipv4_nat_' + hook),), {})
    return result


def _owner(path, paths):
    """Find the object enclosing a provider or consuming rule/entry."""
    for length in range(len(path), 0, -1):
        owner = paths.get(path[:length])
        if owner is not None:
            return owner
    return None


def _references(registrar, configuration, objects, dispatch, consumers):
    # A single inet timeout group owns one native object for each IP family.
    paths = defaultdict(set)
    for key, path in objects.items():
        paths[path].add(key)
    providers = registrar.from_tree(configuration, 'dependency')
    references = registrar.reference_index(registrar.from_tree(configuration, 'depends'))
    for kind, name, path in providers:
        target = _owner(path, paths)
        if target is None:
            continue
        for reference in references.get((kind, name), ()):
            consumer = _owner(reference, paths)
            if consumer is not None:
                for provider in target:
                    consumers[provider].update(consumer)

    firewall = configuration.get('firewall', {})

    # Shared helper assignment references its map, which in turn owns object references.
    if nftables_helpers.configured(firewall):
        mapping = ('map', nftables_helpers.MAP_NAME)
        for name in nftables_helpers.objects(firewall):
            consumers['ct helper', name].add(mapping)
        consumers[mapping].update(('chain', hook) for hook in nftables_helpers.HOOKS)

    # Private source-validation sets are consumed by the family's existing raw chain.
    for family in FAMILIES:
        for kind in source_validation.interface_sets(firewall, family, configuration.get('vrf', {}).get('name', {})):
            target = ('set', source_validation.set_name(family, kind))
            consumers[target].add(('chain', source_validation.chain_name(family)))

    # Global enrollment belongs to the generated forward entrypoint, not a rule path.
    target = firewall.get('global-options', {}).get('flowtable')
    if target is not None:
        consumers['flowtable', nft.nft_flowtable_name(target)].add(('chain', 'forward'))

    # Generated zone maps reference named policies and are consumed by family chains.
    for family in IP_FAMILIES:
        for hook in zones.active_hooks(firewall):
            mapping = ('map', zones.map_name(family, hook))
            consumers[mapping].add(('chain', family + '_' + hook))

        for hook, target in zones.policy_targets(firewall, family):
            mapping = ('map', zones.map_name(family, hook))
            consumers['chain', nft.nft_named_chain(family, target)].add(mapping)

    # Entrypoint chains are generated, so their edges have no schema declarations.
    for key, (targets, _) in dispatch.items():
        for target in targets:
            consumers[target].add(key)

    # Replacing a chain resets its private limits; replacing a limit releases its rule.
    for key, path in objects.items():
        kind = nft.nft_rule_limit_kind(path)
        if key[0] == 'set' and kind is not None:
            chains = paths[path[:-(len(nft.NFT_RULE_LIMIT_PATHS[kind]) + 2)]]
            for chain in chains:
                consumers[chain].add(key)
                consumers[key].add(chain)


def _tracking(configuration, path):
    """Inherited tracking matters only for objects that actually emit it."""
    definition = lookup(configuration, path, {})
    global_options = lookup(configuration, ('firewall', 'global-options'), {})
    if path[:2] == ('firewall', 'group') and path[2] not in {'limit-group', 'counter-group', 'quota-group', 'timeout-group'}:
        return tuple(option in definition or option in global_options for option in ('counter', 'last-used'))
    if path[0] == 'firewall' and path[1] in FAMILIES:
        return {number: tuple(option in rule or option in global_options for option in ('counter', 'last-used'))
                for number, rule in definition.get('rule', {}).items() if 'disable' not in rule}
    return ()


def _reject_responses(configuration, path):
    """Only inherited responses emitted by this chain affect its lifecycle."""
    if path[0] != 'firewall' or path[1] not in FAMILIES:
        return {}

    chain = lookup(configuration, path, {})
    options = lookup(configuration, ('firewall', 'global-options'), {})
    responses = {}
    for number, rule in chain.get('rule', {}).items():
        if 'disable' not in rule and rule.get('action') == 'reject':
            responses[number] = nft.nft_reject_response(rule, options)
    if chain.get('default-action') == 'reject':
        responses['default'] = nft.nft_reject_response({}, options)
    return responses


def _recovery_objects(manager):
    """Recovery cannot trust a previous apply's outcome; replace all owned objects."""
    objects = {('chain', hook) for hook in nft.NFT_FILTER_HOOKS}
    objects.add(('map', nftables_helpers.MAP_NAME))
    objects.update(('ct helper', f'conntrack_helper_{helper}_{protocol}')
                   for helper, transports in nftables_helpers.HELPERS.items() for protocol, _ in transports)
    objects.update(('chain', family + '_' + hook) for family in IP_FAMILIES
                   for hook in nft.NFT_FILTER_HOOKS)
    objects.update(('map', zones.map_name(family, hook)) for family in IP_FAMILIES for hook in zones.HOOKS)
    for hook in NAT_HOOKS.values():
        objects.update({('chain', 'nat_' + hook), ('chain', 'ipv4_nat_' + hook)})
    objects.update(('chain', nft.nft_named_chain(family, name)) for family, name in manager.named_chains())
    objects.update(('map', nft.nft_map_name(family, name)) for family, name in manager.maps())
    objects.update(('set', nft.nft_match_group_name(family, name)) for family, name in manager.match_groups())
    objects.update(('set', nft.nft_icmp_group_name(family, name)) for family, name in manager.icmp_groups())
    objects.update(('set', name) for name in manager.singleton_groups())
    objects.update(('set', name) for name in manager.rule_limits())
    objects.update(manager.named_state())
    objects.update(('flowtable', nft.nft_flowtable_name(name)) for name in manager.flowtables())
    objects.update(('set', source_validation.set_name(family, kind))
                   for family in FAMILIES for kind in source_validation.SET_KINDS)
    return objects


def plan(context, manager):
    before, after = context.previous_effective, context.effective
    old_objects, new_objects = object_paths(before), object_paths(after)
    old_dispatch, new_dispatch = entrypoints(before), entrypoints(after)
    old_zones = zones.maps(before.get('firewall', {}))
    new_zones = zones.maps(after.get('firewall', {}))
    old_keys = old_objects.keys() | old_dispatch.keys() | old_zones.keys()
    new_keys = new_objects.keys() | new_dispatch.keys() | new_zones.keys()

    if context.recovery:
        return {'remove': old_keys | _recovery_objects(manager), 'rebuild': new_keys}

    changed = set(context.get_changed()) | set(context.reapply_paths)
    ancestors = {path[:length] for path in changed for length in range(len(path) + 1)}
    affected = old_keys ^ new_keys
    # The raw chain's owning path does not include its sibling source-validation node.
    # Compare it explicitly even when no interface sets are needed for the default.
    for family in FAMILIES:
        old_validation = source_validation.configuration(before.get('firewall', {}), family)
        new_validation = source_validation.configuration(after.get('firewall', {}), family)
        if old_validation != new_validation:
            affected.add(('chain', source_validation.chain_name(family)))

        # VRF creation/removal changes exclusions without changing firewall configuration.
        old_sets = source_validation.interface_sets(before.get('firewall', {}), family, before.get('vrf', {}).get('name', {}))
        new_sets = source_validation.interface_sets(after.get('firewall', {}), family, after.get('vrf', {}).get('name', {}))
        for kind in old_sets.keys() | new_sets.keys():
            if old_sets.get(kind) != new_sets.get(kind):
                affected.add(('set', source_validation.set_name(family, kind)))

    for key in old_zones.keys() | new_zones.keys():
        if old_zones.get(key) != new_zones.get(key):
            affected.add(key)

    # Log groups have no native nft object, but their packet-copy settings are
    # embedded in consuming rules. Rebuild those chains when a group changes.
    log_path = ('firewall', 'group', 'log-group')
    old_logs = lookup(before, log_path, {})
    new_logs = lookup(after, log_path, {})
    changed_logs = {name for name in old_logs.keys() | new_logs.keys()
                    if old_logs.get(name) != new_logs.get(name)}
    if changed_logs:
        log_references = context.dependencies.reference_index(
            context.dependencies.from_tree(after, 'depends'))
        owners = {path: key for key, path in (old_objects | new_objects).items()}
        for name in changed_logs:
            for reference in log_references.get(('firewall-log-group', name), ()):
                owner = _owner(reference, owners)
                if owner is not None:
                    affected.add(owner)

    response_path = ('firewall', 'global-options', 'reject-response')
    response_changed = lookup(before, response_path, None) != lookup(after, response_path, None)
    old_contexts = nft.nft_interface_contexts(before)
    new_contexts = nft.nft_interface_contexts(after)
    for key, path in (old_objects | new_objects).items():
        if path in ancestors or any(path[:length] in changed for length in range(len(path) + 1)):
            affected.add(key)
        # Omitted timeout states inherit globals; rebuild only if effective values change.
        if key[0] == 'ct timeout':
            old_definition, new_definition = lookup(before, path, None), lookup(after, path, None)
            if old_definition and new_definition:
                old_policy = nftables_timeouts.policy(old_definition, lookup(before, ('firewall', 'global-options'), {}))
                new_policy = nftables_timeouts.policy(new_definition, lookup(after, ('firewall', 'global-options'), {}))
                if old_policy != new_policy:
                    affected.add(key)
        if _tracking(before, path) != _tracking(after, path):
            affected.add(key)
        if response_changed and key[0] == 'chain' and _reject_responses(before, path) != _reject_responses(after, path):
            affected.add(key)
        if key[0] == 'chain' and path[:1] == ('firewall',) and path[1] in FAMILIES:
            identity = tuple(key[1].split('_', 1))
            if path[1] == 'inet' and path[2] != 'name':
                identity = ('inet', key[1])
            old_matches = nft.nft_slave_matches(lookup(before, path, {}), old_contexts.get(identity))
            new_matches = nft.nft_slave_matches(lookup(after, path, {}), new_contexts.get(identity))
            if old_matches != new_matches:
                affected.add(key)
    for key in old_dispatch.keys() | new_dispatch.keys():
        if old_dispatch.get(key) != new_dispatch.get(key):
            affected.add(key)

    # Use both snapshots: old references must be released even when removed now.
    consumers = defaultdict(set)
    _references(context.dependencies, before, old_objects, old_dispatch, consumers)
    _references(context.dependencies, after, new_objects, new_dispatch, consumers)
    pending = deque(affected)
    while pending:
        target = pending.popleft()
        for consumer in consumers[target] - affected:
            affected.add(consumer)
            pending.append(consumer)

    return {'remove': old_keys & affected, 'rebuild': new_keys & affected}
