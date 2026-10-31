"""Schema-declared references: guard removal, without requiring providers to exist."""

from dataclasses import replace
from collections.abc import Mapping

from nvyr.errors import ValidationError
from nvyr.helpers import interface_patterns
from nvyr.lexer import quote
from nvyr.tree import MISSING, apply, lookup, projected_value


def validate_declarations(node, path=()):
    if 'dependency-format' in node and (node.get('kind') != 'tag_node' or 'dependency' not in node
                                      or node['dependency-format'] != '{parent}.{value}'):
        raise ValueError('dependency-format requires {parent}.{value} on a dependency tag node')

    for key in ('dependency', 'depends'):
        if key not in node:
            continue

        value = node[key]
        if (not isinstance(value, str) or not value or any(character.isspace() for character in value)
                or node.get('kind') not in ('tag_node', 'leaf_node') or node.get('valueless')):
            raise ValueError(f"{' '.join(path) or '<root>'}: {key} requires a nonempty type name on a valued leaf or tag node")


class Dependencies:
    def __init__(self, schema):
        self.schema = schema
        self.branches = {}
        self.patterns = {'dependency': [], 'depends': [], 'reapply-on-change': []}
        self.children = {}
        self.watched_fields = {}

        def index(node, path):
            if 'reapply-on-change' in node:
                self.watched_fields.setdefault(node['depends'], set()).update(
                    tuple(field.split()) for field in node['reapply-on-change'])
            relevant = {key for key in self.patterns if key in node}
            for key in relevant:
                self.patterns[key].append(path)

            child_path = (*path, None) if node['kind'] == 'tag_node' else path
            for name, child in node.get('children', {}).items():
                relevant |= index(child, (*child_path, name))

            for category in self.patterns:
                self.children[id(node), category] = [
                    (name, child) for name, child in node.get('children', {}).items()
                    if category in self.branches[id(child)]]
            self.branches[id(node)] = relevant
            return relevant

        index(schema.root, ())

    def identity(self, node, path):
        """Compose a derived provider name from its nearest ancestor tag."""
        if 'dependency-format' not in node:
            return path[-1]

        tags = []
        current = self.schema.root
        for part in path:
            if current['kind'] == 'tag_node':
                tags.append(part)
                current = {'kind': 'node', 'children': current.get('children', {})}
            else:
                current = current['children'][part]

        if len(tags) < 2:
            raise ValueError('dependency-format requires an ancestor tag instance')
        return node['dependency-format'].format(parent=tags[-2], value=tags[-1])

    def affects(self, path, category):
        """Check ancestors and descendants along this path, not every declaration."""
        node = self.schema.root
        position = 0

        while position < len(path):
            if category in node:
                return True
            if category not in self.branches[id(node)]:
                return False

            # A tag's instance name occupies a path component, not a schema child.
            if node['kind'] == 'tag_node':
                position += 1
                if position == len(path):
                    break

            node = node.get('children', {}).get(path[position])
            if node is None:
                return False
            position += 1

        return category in self.branches[id(node)]

    def collect(self, get, keys, category, scope=(), *, identities=None):
        """Collect only annotated branches; paths identify the actual consumers."""
        cursor = self.schema.resolve(scope, validate=False)
        result = set()
        identity_key = 'depends' if category == 'reapply-on-change' else category

        def walk(node, path, instance=False):
            if category not in self.branches[id(node)]:
                return

            if node['kind'] == 'tag_node' and not instance:
                if (identities is not None and category in node and 'dependency-format' not in node
                        and not any(category in self.branches[id(child)] for child in node.get('children', {}).values())):
                    names = {name for kind, name in identities if kind == node[identity_key]}
                else:
                    names = keys(path)

                for name in names:
                    walk(node, (*path, name), True)
                return

            if category in node:
                value = get(path)
                if value is not MISSING:
                    values = [self.identity(node, path)] if instance else value if node.get('multi') else [value]
                    result.update((node[identity_key], name, path) for name in values
                                  if identities is None or (node[identity_key], name) in identities)

                    # Wildcard consumers watch matching providers without pinning
                    # their existence or expanding patterns in saved configuration.
                    if category == 'reapply-on-change' and node[identity_key] == 'interface' and identities:
                        for selector in values:
                            if selector.endswith('*'):
                                result.update((kind, name, path) for kind, name in identities
                                              if kind == 'interface' and interface_patterns.matches(selector, name))

            for name, child in self.children[id(node), category]:
                walk(child, (*path, name))

        walk(cursor.node, scope, cursor.node['kind'] == 'tag_node' and cursor.expect == 'child')
        return result

    def from_tree(self, configuration, category, scope=()):
        """Walk present configuration branches alongside their dependency declarations.

        Complete snapshots can be traversed directly. Candidate journals still
        use collect() and its projected readers to avoid materializing a tree.
        """
        cursor = self.schema.resolve(scope, validate=False)
        result = set()
        identity_key = 'depends' if category == 'reapply-on-change' else category

        def walk(node, value, path, instance=False):
            if value is MISSING or category not in self.branches[id(node)]:
                return

            if node['kind'] == 'tag_node' and not instance:
                for name, options in value.items():
                    walk(node, options, (*path, name), True)
                return

            if category in node:
                values = [self.identity(node, path)] if instance else value if node.get('multi') else [value]
                result.update((node[identity_key], name, path) for name in values)

            if not isinstance(value, Mapping):
                return

            children = node.get('children', {})
            for name in value:
                child = children.get(name)
                if child is not None and category in self.branches[id(child)]:
                    walk(child, value[name], (*path, name))

        walk(cursor.node, lookup(configuration, scope), scope,
             cursor.node['kind'] == 'tag_node' and cursor.expect == 'child')
        return result

    def candidate_readers(self, running, journal):
        def get(path):
            return projected_value(running, journal, path)

        def keys(path):
            # Enumerate possible tag names without materializing a large candidate
            # subtree. Leaf lookups below discard objects deleted by later intents.
            names = set(lookup(running, path, {}))
            for mutation in journal.related(path):
                if mutation.path[:len(path)] == path and len(mutation.path) > len(path):
                    names.add(mutation.path[len(path)])
                elif path[:len(mutation.path)] == mutation.path and mutation.kind == 'set':
                    value = lookup(mutation.value, path[len(mutation.path):], {})
                    if isinstance(value, dict):
                        names.update(value)

            return names

        return get, keys

    @staticmethod
    def reference_index(records):
        result = {}
        for kind, value, path in records:
            result.setdefault((kind, value), set()).add(path)

        return result

    def validate(self, before, after, references):
        remaining = {(kind, value) for kind, value, _ in after}
        removed = {(kind, value) for kind, value, _ in before} - remaining
        blocked = {key: references[key] for key in removed if key in references}

        if blocked:
            messages = []
            for (kind, value), paths in sorted(blocked.items()):
                messages.append(f'Cannot remove {kind} {quote(value)}: referenced by')
                messages.extend('  ' + ' '.join(map(quote, self.schema.command_path(path))) for path in sorted(paths))

            raise ValidationError('\n'.join(messages))

    def check_trees(self, before, after):
        self.validate(self.from_tree(before, 'dependency'), self.from_tree(after, 'dependency'),
                      self.reference_index(self.from_tree(after, 'depends')))

    def check_mutations(self, running, session, mutations):
        if not any(m.kind not in ('ensure', 'add') and self.affects(m.path, 'dependency') for m in mutations):
            return

        scope = mutations[0].path
        for mutation in mutations[1:]:
            while mutation.path[:len(scope)] != scope:
                scope = scope[:-1]

        get, keys = self.candidate_readers(running, session.mutations)
        before = self.collect(get, keys, 'dependency', scope)
        if not before:
            return

        # Preview only the changed branch. A normal interface deletion does not
        # copy the entire interface inventory or the firewall configuration.
        value = get(scope)
        preview = {} if value is MISSING else {'branch': value}
        for mutation in mutations:
            preview = apply(preview, replace(mutation, path=('branch', *mutation.path[len(scope):])))

        value = lookup(preview, ('branch',))
        new_get = lambda path: lookup(value, path[len(scope):])
        new_keys = lambda path: {} if value is MISSING else lookup(value, path[len(scope):], {})
        after = set() if value is MISSING else self.collect(new_get, new_keys, 'dependency', scope)

        if before == after:
            return

        removed = {(kind, name) for kind, name, _ in before} - {(kind, name) for kind, name, _ in after}
        if not removed:
            return

        # Another provider of the same typed identity may remain outside the
        # changed branch. Named providers can be looked up directly by identity.
        final_get = lambda path: new_get(path) if path[:len(scope)] == scope else get(path)
        final_keys = lambda path: new_keys(path) if path[:len(scope)] == scope else keys(path)
        after |= self.collect(final_get, final_keys, 'dependency', identities=removed)

        cached = session.dependency_cache
        if cached is None or cached[0] is not running or cached[1] is not session.mutations:
            cached = (running, session.mutations, self.reference_index(self.collect(get, keys, 'depends')))
            session.dependency_cache = cached

        references = cached[2]
        if any(self.affects(m.path, 'depends') for m in mutations):
            records = {(kind, name, path) for (kind, name), paths in references.items()
                       for path in paths if path[:len(scope)] != scope}
            if value is not MISSING:
                records |= self.collect(new_get, new_keys, 'depends', scope)

            references = self.reference_index(records)

        self.validate(before, after, references)

    def document(self, configuration):
        result = {}
        for category, label in (('dependency', 'providers'), ('depends', 'references')):
            for kind, value, path in sorted(self.from_tree(configuration, category)):
                entry = result.setdefault(kind, {}).setdefault(value, {'providers': [], 'references': []})
                entry[label].append(list(path))

        return result
