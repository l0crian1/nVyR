"""Copy-on-write JSON trees. Published roots and their children must never mutate."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

MISSING = object()


def lookup(tree, path, default=MISSING):
    for part in path:
        if not isinstance(tree, Mapping) or part not in tree:
            return default

        tree = tree[part]

    return tree


def put(tree, path, value):
    if not path:
        return value

    key, *rest = path
    result = dict(tree)
    result[key] = put(tree.get(key, {}), rest, value)

    return result


def remove(tree, path):
    if not path:
        return {}

    key, *rest = path
    if key not in tree:
        return tree

    result = dict(tree)

    if rest:
        result[key] = remove(tree[key], rest)
    else:
        result.pop(key)

    return result


@dataclass(frozen=True)
class Mutation:
    kind: str
    path: tuple[str, ...]
    value: Any = None
    owner: str = ""


@dataclass(slots=True)
class _MutationBranch:
    children: dict = field(default_factory=dict)
    entries: list = field(default_factory=list)


class MutationJournal:
    """Ordered intents indexed by path, without caching a candidate configuration."""

    def __init__(self, mutations=()):
        self.clear()
        for mutation in mutations:
            self.append(mutation)

    def __iter__(self):
        return iter(self._entries.values())

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, index):
        return list(self._entries.values())[index]

    def __eq__(self, other):
        return list(self) == list(other)

    def clear(self):
        self._entries = {}
        self._root = _MutationBranch()
        self._next = 0

    def append(self, mutation):
        branch = self._root
        for part in mutation.path:
            if part not in branch.children:
                branch.children[part] = _MutationBranch()

            branch = branch.children[part]

        # Replace earlier scalar intents at exactly this path, retaining order
        # relative to ancestor deletes and subsequent writes.
        if mutation.kind == 'set':
            for number in branch.entries:
                del self._entries[number]

            branch.entries.clear()

        number = self._next
        self._next += 1
        self._entries[number] = mutation
        branch.entries.append(number)

    def related(self, path):
        """Return ancestor, exact-path and descendant intents in original order."""
        branch = self._root
        numbers = set()
        for part in path:
            numbers.update(branch.entries)
            branch = branch.children.get(part)
            if branch is None:
                break

        if branch is not None:
            pending = [branch]
            while pending:
                branch = pending.pop()
                numbers.update(branch.entries)
                pending.extend(branch.children.values())

        return [self._entries[number] for number in sorted(numbers)]


def apply(tree, mutation):
    return _apply(tree, mutation, put, remove)


def _apply(tree, mutation, write, erase):
    """Share ordered mutation semantics between single edits and batch replay."""
    old = lookup(tree, mutation.path)

    if mutation.kind == "delete":
        return erase(tree, mutation.path)

    if mutation.kind == "ensure":
        return tree if old is not MISSING else write(tree, mutation.path, {})

    if mutation.kind == "add":
        values = [] if old is MISSING else list(old)
        if mutation.value not in values:
            values.append(mutation.value)

        return write(tree, mutation.path, values)

    if mutation.kind == "subtract":
        if old is MISSING:
            return tree

        values = [v for v in old if v != mutation.value]

        return write(tree, mutation.path, values) if values else erase(tree, mutation.path)

    return write(tree, mutation.path, mutation.value)


class _MutationBatch:
    """Own writable copies only for the lifetime of one unpublished overlay."""

    def __init__(self):
        # Retain the copies themselves, not just their IDs: a removed subtree
        # must not let Python reuse an owned ID for a later borrowed value.
        self.owned = {}

    def writable(self, tree):
        if id(tree) in self.owned:
            return tree

        result = dict(tree)
        self.owned[id(result)] = result
        return result

    def put(self, tree, path, value):
        if not path:
            # Values belong to the caller. Clone them only if a later edit
            # descends into them; do not mark an inserted value as batch-owned.
            return value

        key, *rest = path
        result = self.writable(tree)
        result[key] = self.put(result.get(key, {}), rest, value)
        return result

    def remove(self, tree, path):
        if not path:
            return {}

        key, *rest = path
        if key not in tree:
            return tree

        result = self.writable(tree)
        if rest:
            result[key] = self.remove(result[key], rest)
        else:
            result.pop(key)

        return result


def overlay(tree, mutations):
    """Replay in order, cloning each shared dictionary once before editing it.

    Nothing escapes until replay finishes. Running trees and mutation values
    remain untouched, and unchanged branches retain their original identities.
    """
    batch = _MutationBatch()
    for mutation in mutations:
        tree = _apply(tree, mutation, batch.put, batch.remove)

    return tree


def projected_value(tree, mutations, path):
    """Resolve only a requested branch, without constructing a full candidate view."""
    value = lookup(tree, path)

    relevant = mutations.related(path) if isinstance(mutations, MutationJournal) else mutations
    for mutation in relevant:
        # Most large pastes set unrelated leaves at the same depth. They cannot
        # affect this path; skip them without constructing prefix tuples.
        if len(mutation.path) == len(path) and mutation.path != path:
            continue

        if path[:len(mutation.path)] == mutation.path:
            suffix = path[len(mutation.path):]
            if not suffix:
                # Wrap the branch to preserve missing-vs-empty semantics.
                wrapper = {} if value is MISSING else {"value": value}
                local = Mutation(mutation.kind, ("value",), mutation.value)
                value = lookup(apply(wrapper, local), ("value",))
            elif mutation.kind == "delete":
                value = MISSING
            elif mutation.kind == "set":
                value = lookup(mutation.value, suffix)
        elif mutation.path[:len(path)] == path:
            local = Mutation(mutation.kind, mutation.path[len(path):], mutation.value)
            if value is MISSING and local.kind in {'delete', 'subtract'}:
                continue

            value = apply({} if value is MISSING else value, local)

    return value


def changes(before, after, path=()):
    """Yield minimal subtree changes, skipping shared, untouched branches."""
    if before is after or before == after:
        return

    if isinstance(before, Mapping) and isinstance(after, Mapping):
        for key in sorted(before.keys() | after.keys()):
            left, right = before.get(key, MISSING), after.get(key, MISSING)
            if left is MISSING or right is MISSING:
                yield path + (key,), left, right
            else:
                yield from changes(left, right, path + (key,))
    else:
        yield path, before, after


def deleted(before, after, path=()):
    """Read-only path/value removals, including individual multi-leaf values."""
    result = {}

    for location, old, new in changes(before, after, path):
        if new is MISSING:
            result[location] = old
        elif isinstance(old, (list, tuple)) and isinstance(new, (list, tuple)):
            remaining = set(new)
            removed = tuple(value for value in old if value not in remaining)
            if removed:
                result[location] = removed

    return ReadOnlyTree(result)


class ReadOnlyTree(Mapping):
    """Lazy view: modules cannot mutate shared commit state through the public API."""

    def __init__(self, tree):
        self._tree = tree

    def __getitem__(self, key):
        value = self._tree[key]
        if isinstance(value, dict):
            return ReadOnlyTree(value)

        return tuple(value) if isinstance(value, list) else value

    def __iter__(self):
        return iter(self._tree)

    def __len__(self):
        return len(self._tree)
