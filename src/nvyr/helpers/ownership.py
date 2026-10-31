"""Schema script registrations and disjoint configuration ownership."""

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field

from nvyr.tree import MISSING, lookup
from nvyr.helpers.script_schema import ScriptIndex


@dataclass
class ScriptSnapshot:
    """Owner projections, registration values and enclosing-owner relationships.

    Section keys are absolute configuration paths. Each projection excludes
    separately owned children, allowing their changes to be detected independently.
    """
    configuration: Mapping
    sections: dict = field(default_factory=dict)
    registrations: dict = field(default_factory=dict)
    parents: dict = field(default_factory=dict)

    def changed(self, other):
        return {name for name in self.sections.keys() | other.sections.keys()
                if self.sections.get(name, {}) != other.sections.get(name, {})}


class Ownership(ScriptIndex):
    def _project(self, node, value, owner):
        """Select an owner's data, using MISSING for branches owned elsewhere.

        Unchanged leaf subtrees may be shared with the input; callers must treat
        projections as read-only rather than editing the source configuration.
        """
        if node.get('script', {}).get('name', owner) != owner:
            return MISSING

        children = node.get('children', {})
        if not children or not any(self._contains[id(child)] for child in children.values()):
            return value

        def contents(values):
            result = {}
            for key, item in values.items():
                child = children[key]
                projected = self._project(child, item, owner)
                if projected is not MISSING:
                    result[key] = projected

            return result

        if node['kind'] == 'tag_node':
            return {tag: contents(values) for tag, values in value.items()}

        result = contents(value)
        return result if result or self._exclusive[id(node)] or node.get('script') else MISSING

    def snapshot(self, configuration):
        """Index configured sections and deduplicate registrations per owner/key.

        Tag values bind register declarations such as VRF names. Parent links
        retain the concrete enclosing instance needed for creation and rollback.
        """
        result = ScriptSnapshot(configuration)
        registered = {}

        def walk(node, value, path, tags, parent):
            script = node.get('script')
            if script:
                owner = script['name']
                if not parent or parent[0] != owner:
                    result.sections.setdefault(owner, {})[path] = self._project(node, value, owner)
                if parent and parent[0] != owner:
                    result.parents[owner, path] = parent

                parent = (owner, path)

            def register(bindings):
                registration = result.registrations.setdefault(script['name'], {})
                for key, spec in script.get('register', {}).items():
                    item = bindings[spec['tag']] if isinstance(spec, dict) else spec
                    values = registration.setdefault(key, [])
                    seen = registered.setdefault((script['name'], key), set())
                    if item not in seen:
                        seen.add(item)
                        values.append(item)

            # A tag declaration is shared schema; registrations bind separately
            # for each configured instance and its enclosing tag values.
            if node['kind'] == 'tag_node':
                instances = [(path + (tag,), values, tags | {path[-1]: tag})
                             for tag, values in value.items()]
            else:
                instances = [(path, value, tags)]

            for instance, values, bindings in instances:
                if script:
                    register(bindings)

                scope = (parent[0], instance) if parent and node['kind'] == 'tag_node' else parent
                for key, child in node.get('children', {}).items():
                    if key in values and self._contains[id(child)]:
                        walk(child, values[key], instance + (key,), bindings, scope)

        walk(self.root, configuration, (), {}, None)
        return result

    def required_parents(self, before, after):
        """New child sections need successfully created enclosing objects."""
        result = {}
        for (child, _), (parent, scope) in after.parents.items():
            if lookup(before.configuration, scope) is MISSING:
                result.setdefault(child, set()).add(parent)

        return result

    def retained_owners(self, before, after, failed):
        """Keep nested owners consistent when their enclosing object is restored."""
        retained = set(failed)
        while True:
            # Failed removals keep the old parent; rolled-back creations must
            # also remove successful children that would otherwise be orphaned.
            parents = {parent for (child, _), (parent, scope) in before.parents.items()
                       if child in retained and lookup(after.configuration, scope) is MISSING}
            children = {child for (child, _), (parent, scope) in after.parents.items()
                        if parent in retained and lookup(before.configuration, scope) is MISSING}
            related = parents | children
            if related <= retained:
                return retained

            retained.update(related)

    def publish(self, before, after, failed):
        """Choose each owner's successful tree, retaining failed nested sections."""
        if not failed:
            return after

        def walk(node, old, new, owner=None):
            owner = node.get('script', {}).get('name', owner)
            selected = old if owner in failed else new
            if node['kind'] == 'leaf_node':
                return deepcopy(selected) if selected is not MISSING else MISSING

            def contents(a, b, chosen, children, preserve=True):
                a = {} if a is MISSING else a
                b = {} if b is MISSING else b
                result = {}
                for key in a.keys() | b.keys():
                    value = walk(children[key], a.get(key, MISSING), b.get(key, MISSING), owner)
                    if value is not MISSING:
                        result[key] = value

                return result if result or preserve and chosen is not MISSING else MISSING

            if node['kind'] != 'tag_node':
                preserve = self._exclusive[id(node)] or node.get('script') or old is not MISSING or selected == {}
                return contents(old, new, selected, node.get('children', {}), preserve)

            a = {} if old is MISSING else old
            b = {} if new is MISSING else new
            chosen = {} if selected is MISSING else selected
            result = {}
            for tag in a.keys() | b.keys():
                value = contents(a.get(tag, MISSING), b.get(tag, MISSING), chosen.get(tag, MISSING),
                                 node.get('children', {}))
                if value is not MISSING:
                    result[tag] = value

            return result if result or selected is not MISSING else MISSING

        return walk(self.root, before, after)
