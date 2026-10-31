"""Plan dependent script runs using indexed provider identities and field watches."""

from dataclasses import dataclass, field

from nvyr.errors import ValidationError
from nvyr.tree import MISSING, lookup


@dataclass
class ReapplyPlan:
    paths: dict = field(default_factory=dict)
    requires: dict = field(default_factory=dict)

    def order(self, owners, schema, requirements=None):
        """Order changed/reapplied owners by prerequisites, then priority and name."""
        remaining = set(owners) | self.paths.keys()
        edges = {owner: set(values) for owner, values in (requirements or {}).items()}
        for owner, providers in self.requires.items():
            edges.setdefault(owner, set()).update(providers)

        result = []
        while remaining:
            ready = [owner for owner in remaining if not (edges.get(owner, set()) & remaining)]
            # Cyclic watched dependencies have no safe apply order.
            if not ready:
                raise ValidationError('Cyclic configuration reapply dependencies: ' + ', '.join(sorted(remaining)))
            owner = min(ready, key=lambda name: (schema.owners[name][1], name))
            result.append(owner)
            remaining.remove(owner)
        return result

    def retain(self, failed):
        """Keep each affected provider/consumer component consistent on failure."""
        retained = set(failed)
        while True:
            previous = set(retained)
            for consumer, providers in self.requires.items():
                component = providers | {consumer}
                if component & retained:
                    retained.update(component)
            if retained == previous:
                return retained


def watched_values(configuration, pattern, path=()):
    """Expand explicit tag wildcards into concrete watched configuration paths."""
    if not pattern:
        return {path: configuration}
    if not isinstance(configuration, dict):
        return {}

    head, *tail = pattern
    if head == '*':
        values = {}
        for name, child in configuration.items():
            values.update(watched_values(child, tail, (*path, name)))
        return values
    if head not in configuration:
        return {}
    return watched_values(configuration[head], tail, (*path, head))


def plan(registrar, before, after):
    """Plan consumer reruns and provider ordering from effective configuration.

    The result records affected paths per owner and the providers each consumer
    requires. Inspect both trees so reference removal and provider deletion are
    included, even when the consumer's own configuration otherwise stays unchanged.
    """
    schema = registrar.schema
    watched = registrar.watched_fields
    result = ReapplyPlan()

    # Script-level watches cover derived references such as local IP bindings.
    # Only configured consumers participate, including sections being removed.
    changed_watches = {}
    for run_before, watches in ((False, schema.ownership.watches), (True, schema.ownership.before_watches)):
        for owner, paths in watches.items():
            changed_paths = set()
            for pattern in paths:
                old_values = watched_values(before, pattern)
                new_values = watched_values(after, pattern)
                changed_paths.update(path for path in old_values.keys() | new_values.keys()
                                     if old_values.get(path, MISSING) != new_values.get(path, MISSING))
            if changed_paths:
                changed_watches[owner, run_before] = changed_paths

    if changed_watches:
        prior = schema.ownership.snapshot(before)
        current = schema.ownership.snapshot(after)
        changed_owners = prior.changed(current)
        for (owner, run_before), paths in changed_watches.items():
            if owner not in prior.sections and owner not in current.sections:
                continue
            for path in paths:
                result.paths.setdefault(owner, set()).add(path)
                providers = (schema.ownership.owners_at(path) & changed_owners) - {owner}
                if run_before:
                    # Preparatory consumers (such as CT zones) must exist before
                    # their providers activate interfaces. Retention still joins
                    # the same component for failed commits and rollback.
                    for provider in providers:
                        result.requires.setdefault(provider, set()).add(owner)
                else:
                    result.requires.setdefault(owner, set()).update(providers)

    if not watched:
        return result

    snapshots = []
    # Retain old provider identities as well as newly introduced ones.
    for configuration in (before, after):
        values = {}
        for kind, name, path in registrar.from_tree(configuration, 'dependency'):
            if kind in watched:
                values.setdefault((kind, name), {})[path] = {
                    field: lookup(configuration, (*path, *field)) for field in watched[kind]}
        snapshots.append(values)

    old, new = snapshots
    changed = {}
    for identity in old.keys() | new.keys():
        fields = set()
        for relative in watched[identity[0]]:
            # Missing and unconfigured fields compare equally across provider creation.
            a = {path: values[relative] for path, values in old.get(identity, {}).items()
                 if values[relative] is not MISSING}
            b = {path: values[relative] for path, values in new.get(identity, {}).items()
                 if values[relative] is not MISSING}
            if a != b:
                fields.add(relative)
        if fields:
            changed[identity] = fields

    if not changed:
        return result

    for configuration in (before, after):
        references = registrar.collect(lambda path: lookup(configuration, path),
                                       lambda path: lookup(configuration, path, {}),
                                       'reapply-on-change', identities=changed)
        for kind, name, path in references:
            cursor = schema.resolve(path, validate=False)
            fields = {tuple(value.split()) for value in cursor.node.get('reapply-on-change', [])}
            if not fields & changed[kind, name]:
                continue

            consumer = cursor.owner
            result.paths.setdefault(consumer, set()).add(path)
            providers = old.get((kind, name), {}).keys() | new.get((kind, name), {}).keys()
            for provider in providers:
                old_fields = old.get((kind, name), {}).get(provider, {})
                new_fields = new.get((kind, name), {}).get(provider, {})
                if not any(old_fields.get(field, MISSING) != new_fields.get(field, MISSING) for field in fields):
                    continue
                owner = schema.resolve(provider, validate=False).owner
                if owner and owner != consumer:
                    result.requires.setdefault(consumer, set()).add(owner)
    return result
